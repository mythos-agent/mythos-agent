import { describe, it, expect, afterEach, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { createServer } from "../api.js";
import { saveResults } from "../../store/results-store.js";
import { VERSION } from "../../version.js";
import type { ScanResult, Vulnerability } from "../../types/index.js";

// These tests run a real HTTP listener on a random port and exercise the
// full request pipeline (auth, CORS, body-size, routing). The hand-rolled
// middleware in src/server/api.ts — not a framework — is where the subtle
// bugs live, so integration-level tests are much more valuable here than
// pure handler-invocation tests would be.

const tmpDirs: string[] = [];
let server: Server;
let baseUrl: string;
let projectPath: string;

function fixture(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-api-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  tmpDirs.push(dir);
  return dir;
}

beforeAll(async () => {
  projectPath = fixture({ "app.ts": "export const x = 1;\n" });
  server = createServer({ port: 0, host: "127.0.0.1", projectPath });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d && d !== projectPath) fs.rmSync(d, { recursive: true, force: true });
  }
  // Don't delete the shared projectPath — beforeAll set it up for the whole suite.
});

afterAll(() => {
  if (projectPath) fs.rmSync(projectPath, { recursive: true, force: true });
});

describe("HTTP API — /api/health", () => {
  it("returns 200 with current version and a timestamp", async () => {
    const resp = await fetch(`${baseUrl}/api/health`);
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { status: string; version: string; timestamp: string };
    expect(body.status).toBe("ok");
    expect(body.version).toBe(VERSION);
    // Guard against the same hardcoded-version drift that motivated commit
    // 5703298's version.ts fan-out and commit 501f7e7's SARIF driver fix.
    expect(body.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(body.version).not.toBe("1.0.0");
    expect(Date.parse(body.timestamp)).not.toBeNaN();
  });
});

describe("HTTP API — /api/results", () => {
  it("returns 404 with a sensible error when no scan has been saved", async () => {
    // Ensure no leftover results — server uses the shared projectPath
    const resultsPath = path.join(projectPath, ".mythos-agent", "results.json");
    const legacyPath = path.join(projectPath, ".sphinx", "results.json");
    for (const p of [resultsPath, legacyPath]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }

    const resp = await fetch(`${baseUrl}/api/results`);
    expect(resp.status).toBe(404);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toContain("No scan results");
  });

  it("returns 200 with saved findings after saveResults has been called", async () => {
    const finding: Vulnerability = {
      id: "t:1",
      rule: "t:1",
      title: "Test",
      description: "Test finding",
      severity: "high",
      category: "test",
      confidence: "high",
      location: { file: "app.ts", line: 1 },
    };
    const result: ScanResult = {
      projectPath,
      timestamp: new Date().toISOString(),
      duration: 0,
      languages: ["typescript"],
      filesScanned: 1,
      phase1Findings: [finding],
      phase2Findings: [],
      confirmedVulnerabilities: [finding],
      dismissedCount: 0,
      chains: [],
    };
    saveResults(projectPath, result);

    const resp = await fetch(`${baseUrl}/api/results`);
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as ScanResult;
    expect(body.confirmedVulnerabilities).toHaveLength(1);
    expect(body.confirmedVulnerabilities[0].title).toBe("Test");
  });
});

describe("HTTP API — /api/scan", () => {
  it("runs a scan against the configured project path and returns a summary", async () => {
    const resp = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as {
      findings: number;
      filesScanned: number;
      languages: string[];
      tools: string[];
      duration: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    expect(typeof body.findings).toBe("number");
    expect(typeof body.filesScanned).toBe("number");
    expect(body.tools).toContain("built-in");
    expect(typeof body.duration).toBe("number");
  });

  it("returns 400 on an invalid JSON body (not a silent empty-body fallback)", async () => {
    const resp = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{ not json",
    });
    expect(resp.status).toBe(400);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toBe("Invalid JSON body");
  });
});

describe("HTTP API — CORS", () => {
  it("reflects allowed localhost origins in Access-Control-Allow-Origin", async () => {
    const resp = await fetch(`${baseUrl}/api/health`, {
      headers: { Origin: "http://localhost:3000" },
    });
    expect(resp.headers.get("access-control-allow-origin")).toBe("http://localhost:3000");
  });

  it("reflects 127.0.0.1 origins too", async () => {
    const resp = await fetch(`${baseUrl}/api/health`, {
      headers: { Origin: "http://127.0.0.1:5173" },
    });
    expect(resp.headers.get("access-control-allow-origin")).toBe("http://127.0.0.1:5173");
  });

  it("does NOT reflect remote origins (prevents dashboard CSRF from foreign sites)", async () => {
    const resp = await fetch(`${baseUrl}/api/health`, {
      headers: { Origin: "https://evil.example.com" },
    });
    expect(resp.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("responds to OPTIONS preflight with 204 and no body", async () => {
    const resp = await fetch(`${baseUrl}/api/scan`, {
      method: "OPTIONS",
      headers: { Origin: "http://localhost:3000" },
    });
    expect(resp.status).toBe(204);
    expect(resp.headers.get("access-control-allow-methods")).toContain("POST");
  });
});

describe("HTTP API — routing", () => {
  it("returns 404 with a list of endpoints for an unknown route", async () => {
    const resp = await fetch(`${baseUrl}/api/does-not-exist`);
    expect(resp.status).toBe(404);
    const body = (await resp.json()) as { error: string; endpoints: string[] };
    expect(body.error).toBe("Not found");
    // Having the error body list valid routes makes debugging misconfigured
    // clients much faster — this was intentional behavior, pin it.
    expect(body.endpoints.length).toBeGreaterThan(0);
    expect(body.endpoints).toContain("GET /api/health");
  });
});

describe("HTTP API — API key auth (separate server instance)", () => {
  let authServer: Server;
  let authBase: string;
  const SECRET = "test-secret-123";

  beforeAll(async () => {
    // Note: createServer mutates a module-level serverConfig — so this suite
    // must run AFTER the main-server tests have finished, which Vitest
    // guarantees inside the same file for sequential describe blocks.
    // Intentionally NOT isolated, because the route registry is module state.
    authServer = createServer({ port: 0, host: "127.0.0.1", projectPath, apiKey: SECRET });
    await new Promise<void>((resolve) => authServer.listen(0, "127.0.0.1", () => resolve()));
    const addr = authServer.address() as AddressInfo;
    authBase = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => authServer.close(() => resolve()));
  });

  it("rejects requests with no Authorization header as 401", async () => {
    const resp = await fetch(`${authBase}/api/health`);
    expect(resp.status).toBe(401);
    const body = (await resp.json()) as { error: string };
    expect(body.error).toBe("Unauthorized");
  });

  it("rejects requests with a wrong bearer token as 401", async () => {
    const resp = await fetch(`${authBase}/api/health`, {
      headers: { Authorization: "Bearer wrong-key" },
    });
    expect(resp.status).toBe(401);
  });

  it("accepts requests with the correct bearer token", async () => {
    const resp = await fetch(`${authBase}/api/health`, {
      headers: { Authorization: `Bearer ${SECRET}` },
    });
    expect(resp.status).toBe(200);
  });
});
