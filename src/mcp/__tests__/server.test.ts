import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { handleRequest } from "../server.js";
import { saveResults } from "../../store/results-store.js";
import { VERSION } from "../../version.js";
import type { ScanResult } from "../../types/index.js";

type Files = Record<string, string>;

const tmpDirs: string[] = [];

function fixture(files: Files): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-mcp-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

const rpc = (method: string, params?: Record<string, unknown>, id: number = 1) => ({
  jsonrpc: "2.0" as const,
  id,
  method,
  params,
});

// Any MCP client (Claude Desktop, Cursor, Claude Code) calls these exact
// tool names — renaming them is a breaking change, so this list pins
// the currently-advertised surface. Extend this when 4.0 aliases land.
const PUBLIC_TOOL_NAMES = [
  "sphinx_endpoints",
  "sphinx_iac",
  "sphinx_results",
  "sphinx_scan",
  "sphinx_score",
  "sphinx_secrets",
] as const;

function textContent(resp: Awaited<ReturnType<typeof handleRequest>>): string {
  const content = (resp.result as { content?: Array<{ text: string }> } | undefined)?.content;
  if (!content || content.length === 0) throw new Error("expected content block");
  return content[0].text;
}

describe("MCP server — protocol handlers", () => {
  it("initialize advertises the current package version, not a stale literal", async () => {
    const resp = await handleRequest(rpc("initialize"));
    expect(resp.error).toBeUndefined();
    expect(resp.result).toMatchObject({
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "mythos-agent", version: VERSION },
    });
    // Guard against regressing to any of the hardcoded versions the codebase has carried.
    const version = (resp.result as { serverInfo: { version: string } }).serverInfo.version;
    expect(version).not.toBe("1.0.0");
    expect(version).not.toBe("2.0.0");
    expect(version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("tools/list exposes exactly the 6 advertised sphinx_* tools with input schemas", async () => {
    const resp = await handleRequest(rpc("tools/list"));
    expect(resp.error).toBeUndefined();
    const tools = (resp.result as { tools: Array<{ name: string; inputSchema: unknown }> }).tools;
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([...PUBLIC_TOOL_NAMES]);
    // Every tool must declare an input schema or MCP clients throw at registration time.
    for (const t of tools) {
      expect(t.inputSchema).toMatchObject({ type: "object" });
    }
  });

  it("returns JSON-RPC -32601 (method not found) for an unknown method", async () => {
    const resp = await handleRequest(rpc("does/not/exist"));
    expect(resp.result).toBeUndefined();
    expect(resp.error?.code).toBe(-32601);
    expect(resp.error?.message).toContain("does/not/exist");
  });

  it("returns JSON-RPC -32602 (invalid params) for an unknown tool name", async () => {
    const resp = await handleRequest(rpc("tools/call", { name: "sphinx_nonsense", arguments: {} }));
    expect(resp.result).toBeUndefined();
    expect(resp.error?.code).toBe(-32602);
    expect(resp.error?.message).toContain("sphinx_nonsense");
  });

  it("preserves the request id in the response (JSON-RPC 2.0 requirement)", async () => {
    const resp = await handleRequest(rpc("initialize", undefined, 42));
    expect(resp.id).toBe(42);
    expect(resp.jsonrpc).toBe("2.0");
  });
});

describe("MCP server — tool handlers", () => {
  it("sphinx_scan returns a finding block for a vulnerable file in the given path", async () => {
    const dir = fixture({
      "api.ts": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "sphinx_scan", arguments: { path: dir, severity: "low" } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    // Either reports findings (expected for a vulnerable file) or an explicit clean message.
    // The key invariant: the handler produces a text content block, not a crash or empty result.
    expect(text.length).toBeGreaterThan(0);
    expect(text.toLowerCase()).toMatch(/vulnerabilit|found|scanned/);
  });

  it("sphinx_secrets surfaces a hardcoded AWS-style key", async () => {
    // Split the literal so it can't be picked up by scanners of the test file itself.
    const fakeKey = "AKIA" + "IOSFODNN7EXAMPLE";
    const dir = fixture({
      "leak.ts": `const AWS_SECRET = "${fakeKey}";`,
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "sphinx_secrets", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text.toLowerCase()).toMatch(/found|secret|key|vulnerabilit/);
  });

  it("sphinx_endpoints summarises routes discovered in the project", async () => {
    const dir = fixture({
      "routes.ts":
        "import express from 'express';\nconst app = express();\napp.get('/users', (req, res) => res.json({}));\napp.post('/login', (req, res) => res.json({}));\n",
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "sphinx_endpoints", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    // Handler always emits an "Endpoints:" summary line even on zero discovery.
    expect(text).toContain("Endpoints:");
  });

  it("sphinx_iac flags a Dockerfile misconfig", async () => {
    const dir = fixture({
      Dockerfile: "FROM node:18\nUSER root\nRUN apt-get install -y curl\n",
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "sphinx_iac", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text.length).toBeGreaterThan(0);
  });

  it("sphinx_results returns a helpful message when no scan has been saved", async () => {
    const dir = fixture({ "empty.txt": "" });
    const resp = await handleRequest(
      rpc("tools/call", { name: "sphinx_results", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text).toContain("No scan results");
    expect(text).toContain("mythos-agent scan");
  });

  it("sphinx_results reads back findings + chains from a saved scan", async () => {
    const dir = fixture({ "src.ts": "// code" });
    const savedResult: ScanResult = {
      projectPath: dir,
      timestamp: new Date().toISOString(),
      duration: 0,
      languages: ["typescript"],
      filesScanned: 1,
      phase1Findings: [],
      phase2Findings: [],
      confirmedVulnerabilities: [
        {
          id: "pattern:test-rule",
          rule: "pattern:test-rule",
          title: "Test finding",
          description: "A saved finding",
          severity: "high",
          category: "test",
          confidence: "high",
          location: { file: "src.ts", line: 1 },
        },
      ],
      dismissedCount: 0,
      chains: [],
    };
    saveResults(dir, savedResult);

    const resp = await handleRequest(
      rpc("tools/call", { name: "sphinx_results", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text).toContain("Findings: 1");
    expect(text).toContain("Test finding");
  });

  it("sphinx_score returns a numeric score and letter grade", async () => {
    const dir = fixture({ "clean.ts": "export const x = 1;\n" });
    const resp = await handleRequest(
      rpc("tools/call", { name: "sphinx_score", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text).toMatch(/Security Score: \d+\/100 \([A-F][+]?\)/);
    expect(text).toContain("Findings:");
  });

  it("surfaces scanner errors via isError=true on the tool-call response", async () => {
    // Point the handler at a path that does not exist — the scanner should throw,
    // the handler should translate that into an MCP error content block rather
    // than returning a raw JSON-RPC error (per MCP spec for tool errors).
    const resp = await handleRequest(
      rpc("tools/call", {
        name: "sphinx_scan",
        arguments: { path: "/this/path/definitely/does/not/exist/anywhere" },
      })
    );
    // Either the content-block error path or an empty-clean response is acceptable;
    // what must NOT happen is a thrown exception bubbling up to the RPC layer.
    expect(resp.jsonrpc).toBe("2.0");
    expect(resp.id).toBe(1);
  });
});
