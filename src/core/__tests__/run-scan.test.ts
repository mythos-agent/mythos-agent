import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { runScan, type PhaseEvent } from "../run-scan.js";
import { loadConfig } from "../../config/config.js";

const tmpDirs: string[] = [];

function fixture(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-runscan-"));
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

describe("runScan — shape + defaults", () => {
  it("runs against an empty-ish project and returns a well-formed output", async () => {
    const dir = fixture({ "app.ts": "export const x = 1;\n" });
    const out = await runScan(dir);
    expect(out).toMatchObject({
      findings: expect.any(Array),
      patternFindings: expect.any(Array),
      deterministicFindings: expect.any(Array),
      filesScanned: expect.any(Number),
      languages: expect.any(Array),
      toolsRun: expect.any(Array),
      durationMs: expect.any(Number),
    });
    expect(out.durationMs).toBeGreaterThanOrEqual(0);
    // External tools are opt-in; default runs must not populate toolsRun.
    expect(out.toolsRun).toEqual([]);
  });

  it("`findings` equals the concatenation of patternFindings + deterministicFindings", async () => {
    // The CLI relies on this split to feed only patternFindings through the
    // AIAnalyzer Phase 2 verifier while passing deterministicFindings
    // through untouched. Invariant: the two must partition `findings`.
    const dir = fixture({ "app.ts": "export const x = 1;\n" });
    const out = await runScan(dir);
    expect(out.findings).toEqual([...out.patternFindings, ...out.deterministicFindings]);
  });

  it("filesScanned reflects the pattern scanner's view of the project", async () => {
    const dir = fixture({
      "a.ts": "export const a = 1;\n",
      "b.ts": "export const b = 2;\n",
      "README.md": "# Not scanned\n",
    });
    const out = await runScan(dir);
    expect(out.filesScanned).toBeGreaterThanOrEqual(2);
  });
});

describe("runScan — per-scanner opt-out flags", () => {
  it("skips the SecretsScanner phase when `secrets: false`", async () => {
    const dir = fixture({ "app.ts": "" });
    const phases: PhaseEvent[] = [];
    await runScan(dir, { secrets: false, onPhase: (e) => phases.push(e) });
    const secretsPhases = phases.filter((p) => p.id === "secrets");
    expect(secretsPhases).toHaveLength(0);
  });

  it("skips the IacScanner phase when `iac: false`", async () => {
    const dir = fixture({ "app.ts": "" });
    const phases: PhaseEvent[] = [];
    await runScan(dir, { iac: false, onPhase: (e) => phases.push(e) });
    expect(phases.filter((p) => p.id === "iac")).toHaveLength(0);
  });

  it("skips the RedosScanner phase when `redos: false`", async () => {
    const dir = fixture({ "app.ts": "" });
    const phases: PhaseEvent[] = [];
    await runScan(dir, { redos: false, onPhase: (e) => phases.push(e) });
    expect(phases.filter((p) => p.id === "redos")).toHaveLength(0);
  });

  it("runs all 16 deterministic scanners by default (pattern always on; 15 flag-gated)", async () => {
    const dir = fixture({ "app.ts": "" });
    const phaseStarts = new Set<string>();
    await runScan(dir, {
      onPhase: (e) => {
        if (e.state === "start") phaseStarts.add(e.id);
      },
    });
    // Guard against a future scanner being added to runScan without being
    // wired into the default-on set.
    expect(phaseStarts).toEqual(
      new Set([
        "pattern",
        "secrets",
        "deps",
        "iac",
        "llm",
        "api-sec",
        "cloud",
        "headers",
        "jwt",
        "session",
        "biz-logic",
        "crypto",
        "privacy",
        "race-conditions",
        "redos",
        "redirect-headers",
      ])
    );
  });
});

describe("runScan — pre-resolved config", () => {
  it("honors a caller-supplied `config` and does not re-load from disk", async () => {
    // The CLI mutates config.scan.include/exclude in --diff mode before
    // calling runScan. If runScan ignored the passed-in config and re-ran
    // loadConfig(), those diff-mode mutations would be silently discarded
    // and the scan would cover the whole project instead of just changed
    // files. Pin this invariant.
    const dir = fixture({
      "included.ts": "export const a = 1;\n",
      "excluded.ts": "export const b = 2;\n",
    });
    const config = loadConfig(dir);
    config.scan.include = ["included.ts"]; // deliberately narrow
    config.scan.exclude = [];

    const out = await runScan(dir, { config });
    // PatternScanner honors config.scan.include, so filesScanned reflects
    // the narrowed set, not the whole tempdir.
    expect(out.filesScanned).toBe(1);
  });
});

describe("runScan — includeExternalTools gate", () => {
  it("does NOT invoke external tools when the flag is absent (default)", async () => {
    const dir = fixture({ "app.ts": "" });
    const phases: PhaseEvent[] = [];
    await runScan(dir, { onPhase: (e) => phases.push(e) });
    expect(phases.filter((p) => p.id === "external-tools")).toHaveLength(0);
  });

  it("DOES invoke external tools when `includeExternalTools: true`", async () => {
    const dir = fixture({ "app.ts": "" });
    const phases: PhaseEvent[] = [];
    await runScan(dir, { includeExternalTools: true, onPhase: (e) => phases.push(e) });
    const extPhases = phases.filter((p) => p.id === "external-tools");
    // Should fire exactly one start + one end (or error) event.
    expect(extPhases.length).toBeGreaterThanOrEqual(1);
    expect(extPhases[0].state).toBe("start");
  });
});

describe("runScan — onPhase callback lifecycle", () => {
  it("emits matched start/end events in order for each enabled scanner", async () => {
    const dir = fixture({ "app.ts": "" });
    const events: PhaseEvent[] = [];
    await runScan(dir, {
      secrets: true,
      deps: false,
      iac: false,
      llm: false,
      apiSec: false,
      cloud: false,
      headers: false,
      jwt: false,
      session: false,
      bizLogic: false,
      crypto: false,
      privacy: false,
      raceConditions: false,
      redos: false,
      redirectHeaders: false,
      onPhase: (e) => events.push(e),
    });

    // pattern + secrets only — 4 events total (2 start + 2 end/error).
    expect(events).toHaveLength(4);
    expect(events[0]).toMatchObject({ id: "pattern", state: "start" });
    expect(events[1].id).toBe("pattern");
    expect(["end", "error"]).toContain(events[1].state);
    expect(events[2]).toMatchObject({ id: "secrets", state: "start" });
    expect(events[3].id).toBe("secrets");
  });

  it("end events on successful phases carry durationMs and a findings count", async () => {
    const dir = fixture({ "app.ts": "" });
    const events: PhaseEvent[] = [];
    await runScan(dir, {
      secrets: false,
      deps: false,
      iac: false,
      llm: false,
      apiSec: false,
      cloud: false,
      headers: false,
      jwt: false,
      session: false,
      bizLogic: false,
      crypto: false,
      privacy: false,
      raceConditions: false,
      redos: false,
      onPhase: (e) => events.push(e),
    });
    const patternEnd = events.find((e) => e.id === "pattern" && e.state === "end");
    expect(patternEnd).toBeDefined();
    expect(patternEnd?.durationMs).toBeGreaterThanOrEqual(0);
    expect(typeof patternEnd?.findings).toBe("number");
  });

  it("is optional — runScan works without onPhase", async () => {
    const dir = fixture({ "app.ts": "" });
    // Does not throw.
    const out = await runScan(dir);
    expect(out.findings).toBeDefined();
  });
});
