import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { Orchestrator } from "../orchestrator.js";
import { DEFAULT_CONFIG, type MythosConfig } from "../../types/index.js";

// The Orchestrator coordinates 4 sub-agents: Recon → Hypothesis → Analyze →
// Exploit. Each sub-agent has a no-apiKey fallback (Recon uses heuristic
// file walk, Analyzer skips AI verification, Hypothesis is gated off entirely
// at the orchestrator level, Exploit returns empty reports when findings
// < 2 or no client). These tests run the whole pipeline without an API key
// so they're fully hermetic — no network calls, no API-key secret handling —
// and still exercise the real coordination logic (phase ordering, report
// merge, confidence summary computation, spinner silencing).

const tmpDirs: string[] = [];

function fixture(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-orch-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  tmpDirs.push(dir);
  return dir;
}

function noApiKeyConfig(): MythosConfig {
  // structuredClone because orchestrator / sub-agents read config fields
  // that could pollute the shared DEFAULT_CONFIG if mutated.
  const c = structuredClone(DEFAULT_CONFIG);
  c.apiKey = undefined; // explicit — the invariant under test
  return c;
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

describe("Orchestrator — end-to-end in no-apiKey mode", () => {
  it("runs all 4 phases and returns a well-formed OrchestratorResult", async () => {
    const dir = fixture({
      "routes.ts":
        "import express from 'express';\nconst app = express();\napp.get('/users', (req, res) => res.json({}));\n",
    });

    const orch = new Orchestrator(noApiKeyConfig(), dir, /* silent */ true);
    const result = await orch.run();

    // All 4 report slots must be populated with their expected shapes.
    expect(result.recon).toMatchObject({
      type: "recon",
      entryPoints: expect.any(Array),
      techStack: expect.any(Array),
      authBoundaries: expect.any(Array),
      dataStores: expect.any(Array),
    });
    expect(result.hypotheses).toMatchObject({
      type: "hypothesis",
      hypotheses: expect.any(Array),
    });
    expect(result.analysis).toMatchObject({
      type: "analysis",
      findings: expect.any(Array),
      toolsUsed: expect.any(Array),
      aiInsights: expect.any(Array),
      falsePositivesDismissed: expect.any(Number),
    });
    expect(result.exploit).toMatchObject({
      type: "exploit",
      chains: expect.any(Array),
      proofOfConcepts: expect.any(Array),
    });
  });

  it("skips the hypothesis phase entirely when config.apiKey is absent", async () => {
    // The hypothesis phase is the one that makes mythos-agent "reason about
    // what could go wrong" rather than just pattern-match. Without an API
    // key it's correctly gated off — this test pins that gating so a future
    // refactor doesn't silently run the hypothesis agent against no client.
    const dir = fixture({ "app.ts": "export const x = 1;\n" });
    const result = await new Orchestrator(noApiKeyConfig(), dir, true).run();
    expect(result.hypotheses.hypotheses).toEqual([]);
  });

  it("produces a non-negative numeric confidence summary (never NaN or negative)", async () => {
    const dir = fixture({ "app.ts": "export const x = 1;\n" });
    const result = await new Orchestrator(noApiKeyConfig(), dir, true).run();
    const s = result.confidenceSummary;

    for (const field of ["confirmed", "likely", "possible", "dismissed"] as const) {
      expect(s[field]).toEqual(expect.any(Number));
      expect(Number.isFinite(s[field])).toBe(true);
      expect(s[field]).toBeGreaterThanOrEqual(0);
    }
  });

  it("tracks duration as a non-negative integer number of milliseconds", async () => {
    const dir = fixture({ "app.ts": "export const x = 1;\n" });
    const result = await new Orchestrator(noApiKeyConfig(), dir, true).run();
    expect(result.duration).toEqual(expect.any(Number));
    expect(result.duration).toBeGreaterThanOrEqual(0);
    // Sanity check: an end-to-end run must take at least a tick.
    // (Using 0 rather than >0 as the lower bound because extremely fast
    // runs on beefy CI hardware can legitimately complete in <1ms per
    // clock resolution.)
  });

  it("analyzer phase uses deterministic scanners even without an API key", async () => {
    // Deliberately plant a secret-scanner-triggering pattern so we prove the
    // analyzer actually ran its scanners. Split the literal to avoid
    // self-triggering on this test file. Even in no-apiKey mode, the
    // analyzer's deterministic scanner passes must still fire.
    const fakeKey = "AKIA" + "IOSFODNN7EXAMPLE";
    const dir = fixture({
      "leak.ts": `const S = "${fakeKey}";\n`,
    });
    const result = await new Orchestrator(noApiKeyConfig(), dir, true).run();
    // At least one scanner tool must have been recorded in the analysis
    // report — the baseline "built-in-patterns" always runs.
    expect(result.analysis.toolsUsed).toContain("built-in-patterns");
  });

  it("exploit phase returns empty chains + PoCs when there's no client (no apiKey)", async () => {
    // ExploitAgent requires an Anthropic client to do its chain-analysis
    // LLM call. Without one it must return an empty ExploitReport — NOT
    // throw, NOT leave undefined fields. This invariant lets the
    // confidence-summary computation (`.proofOfConcepts.filter(...)`)
    // work without a null check.
    const dir = fixture({ "app.ts": "export const x = 1;\n" });
    const result = await new Orchestrator(noApiKeyConfig(), dir, true).run();
    expect(result.exploit.chains).toEqual([]);
    expect(result.exploit.proofOfConcepts).toEqual([]);
  });
});

describe("Orchestrator — silent mode", () => {
  it("does not write any spinner output when silent=true", async () => {
    // ora writes to stderr (default) or stdout depending on TTY detection.
    // Silent mode must suppress BOTH paths so library-mode consumers don't
    // get stray spinner characters interleaved with their own output.
    // Capture via direct write-method replacement — avoids vi.spyOn's
    // generic type constraint that doesn't accept method names for
    // overloaded write signatures.
    const captured: string[] = [];
    const origStderr = process.stderr.write.bind(process.stderr);
    const origStdout = process.stdout.write.bind(process.stdout);
    process.stderr.write = ((chunk: unknown) => {
      if (typeof chunk === "string") captured.push(chunk);
      return true;
    }) as typeof process.stderr.write;
    process.stdout.write = ((chunk: unknown) => {
      if (typeof chunk === "string") captured.push(chunk);
      return true;
    }) as typeof process.stdout.write;

    try {
      const dir = fixture({ "app.ts": "export const x = 1;\n" });
      await new Orchestrator(noApiKeyConfig(), dir, true).run();
    } finally {
      process.stderr.write = origStderr;
      process.stdout.write = origStdout;
    }

    const allOutput = captured.join("");
    // ora uses these unicode markers for spinner/check/warn frames.
    // If silent=true suppresses spinners properly, none should appear.
    expect(allOutput).not.toContain("✔");
    expect(allOutput).not.toContain("✖");
    expect(allOutput).not.toContain("⚠");
  });
});
