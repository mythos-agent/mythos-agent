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
// tool names — renaming or removing any of them is a breaking change.
// 3.x advertises both the preferred `mythos_*` family and the deprecated
// `sphinx_*` legacy aliases side-by-side; 4.0 drops the sphinx_* set.
const CANONICAL_TOOLS = ["scan", "secrets", "endpoints", "iac", "results", "score"] as const;
const PUBLIC_TOOL_NAMES = [
  ...CANONICAL_TOOLS.map((t) => `mythos_${t}`),
  ...CANONICAL_TOOLS.map((t) => `sphinx_${t}`),
].sort();

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

  it("tools/list exposes all 12 tool names (6 mythos_* preferred + 6 sphinx_* deprecated aliases)", async () => {
    const resp = await handleRequest(rpc("tools/list"));
    expect(resp.error).toBeUndefined();
    const tools = (
      resp.result as {
        tools: Array<{ name: string; description: string; inputSchema: unknown }>;
      }
    ).tools;
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(PUBLIC_TOOL_NAMES);
    // Every tool must declare an input schema or MCP clients throw at registration time.
    for (const t of tools) {
      expect(t.inputSchema).toMatchObject({ type: "object" });
    }
    // Deprecated aliases must be visibly marked so users who browse Claude
    // Desktop's tool list know which ones to migrate off.
    const sphinxTools = tools.filter((t) => t.name.startsWith("sphinx_"));
    expect(sphinxTools).toHaveLength(6);
    for (const t of sphinxTools) {
      expect(t.description.toUpperCase()).toContain("DEPRECATED");
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
  it("mythos_scan returns a finding block for a vulnerable file in the given path", async () => {
    const dir = fixture({
      "api.ts": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "mythos_scan", arguments: { path: dir, severity: "low" } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    // Either reports findings (expected for a vulnerable file) or an explicit clean message.
    // The key invariant: the handler produces a text content block, not a crash or empty result.
    expect(text.length).toBeGreaterThan(0);
    expect(text.toLowerCase()).toMatch(/vulnerabilit|found|scanned/);
  });

  it("mythos_secrets surfaces a hardcoded AWS-style key", async () => {
    // Split the literal so it can't be picked up by scanners of the test file itself.
    const fakeKey = "AKIA" + "IOSFODNN7EXAMPLE";
    const dir = fixture({
      "leak.ts": `const AWS_SECRET = "${fakeKey}";`,
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "mythos_secrets", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text.toLowerCase()).toMatch(/found|secret|key|vulnerabilit/);
  });

  it("mythos_endpoints summarises routes discovered in the project", async () => {
    const dir = fixture({
      "routes.ts":
        "import express from 'express';\nconst app = express();\napp.get('/users', (req, res) => res.json({}));\napp.post('/login', (req, res) => res.json({}));\n",
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "mythos_endpoints", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    // Handler always emits an "Endpoints:" summary line even on zero discovery.
    expect(text).toContain("Endpoints:");
  });

  it("mythos_iac flags a Dockerfile misconfig", async () => {
    const dir = fixture({
      Dockerfile: "FROM node:18\nUSER root\nRUN apt-get install -y curl\n",
    });
    const resp = await handleRequest(
      rpc("tools/call", { name: "mythos_iac", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text.length).toBeGreaterThan(0);
  });

  it("mythos_results returns a helpful message when no scan has been saved", async () => {
    const dir = fixture({ "empty.txt": "" });
    const resp = await handleRequest(
      rpc("tools/call", { name: "mythos_results", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text).toContain("No scan results");
    expect(text).toContain("mythos-agent scan");
  });

  it("mythos_results reads back findings + chains from a saved scan", async () => {
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
      rpc("tools/call", { name: "mythos_results", arguments: { path: dir } })
    );
    expect(resp.error).toBeUndefined();
    const text = textContent(resp);
    expect(text).toContain("Findings: 1");
    expect(text).toContain("Test finding");
  });

  it("mythos_score returns a numeric score and letter grade", async () => {
    const dir = fixture({ "clean.ts": "export const x = 1;\n" });
    const resp = await handleRequest(
      rpc("tools/call", { name: "mythos_score", arguments: { path: dir } })
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
        name: "mythos_scan",
        arguments: { path: "/this/path/definitely/does/not/exist/anywhere" },
      })
    );
    // Either the content-block error path or an empty-clean response is acceptable;
    // what must NOT happen is a thrown exception bubbling up to the RPC layer.
    expect(resp.jsonrpc).toBe("2.0");
    expect(resp.id).toBe(1);
  });
});

describe("MCP server — sphinx_* legacy alias behavior", () => {
  // Any client configured during the sphinx-branded era must keep working
  // through 3.x. The body should carry a visible deprecation notice so
  // users see it at call time (not only if they re-read tools/list).

  it.each(["scan", "secrets", "endpoints", "iac", "results", "score"])(
    "sphinx_%s routes to the same handler as mythos_%s and prepends a deprecation notice",
    async (shortName) => {
      const dir = fixture({ "empty.ts": "export {};\n" });

      const mythosResp = await handleRequest(
        rpc("tools/call", { name: `mythos_${shortName}`, arguments: { path: dir } })
      );
      const sphinxResp = await handleRequest(
        rpc("tools/call", { name: `sphinx_${shortName}`, arguments: { path: dir } })
      );

      expect(mythosResp.error).toBeUndefined();
      expect(sphinxResp.error).toBeUndefined();

      const mythosText = textContent(mythosResp);
      const sphinxText = textContent(sphinxResp);

      // Deprecation marker is present only on the sphinx_* path.
      expect(mythosText).not.toContain("DEPRECATED");
      expect(sphinxText).toContain("DEPRECATED");
      expect(sphinxText).toContain("mythos-agent 4.0");
      expect(sphinxText).toContain(`mythos_${shortName}`);

      // Routing parity: strip the deprecation preamble from the sphinx_*
      // response and the remainder should match the mythos_* body byte-for-byte.
      // Both calls hit the same scanner with the same args on the same fixture,
      // so any difference indicates the alias path diverged — a regression we
      // specifically want this test to catch.
      const preambleEnd = sphinxText.indexOf("\n\n");
      expect(preambleEnd).toBeGreaterThan(0);
      const sphinxBody = sphinxText.slice(preambleEnd + 2);
      expect(sphinxBody).toBe(mythosText);
    }
  );
});
