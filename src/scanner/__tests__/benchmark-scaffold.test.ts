import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { JwtScanner } from "../jwt-scanner.js";
import { HeadersScanner } from "../headers-scanner.js";
import { SessionScanner } from "../session-scanner.js";
import { BusinessLogicScanner } from "../business-logic-scanner.js";
import { SecretsScanner } from "../secrets-scanner.js";
import { IacScanner } from "../iac-scanner.js";
import { LlmSecurityScanner } from "../llm-security-scanner.js";
import { ApiSecurityScanner } from "../api-security-scanner.js";
import { CloudSecurityScanner } from "../cloud-scanner.js";
import { CryptoScanner } from "../crypto-scanner.js";
import { PrivacyScanner } from "../privacy-scanner.js";
import { RaceConditionScanner } from "../race-condition-scanner.js";
import { RedosScanner } from "../redos-scanner.js";
import type { Vulnerability } from "../../types/index.js";

/**
 * Sphinx-Benchmark v0.1 scaffold runner.
 *
 * Enumerates every case under `benchmark/cases/SPX-BENCH-*`, loads its
 * `case.yml`, runs the wired deterministic scanners against the case's
 * `vulnerable/` directory, and fails if any `expected_findings` entry
 * has no matching produced finding.
 *
 * Covered today: the five deterministic scanners we can reliably point
 * at a directory without additional config. PatternScanner + the AI
 * analyzer loop are deliberately excluded from v0.1 — they need
 * `MythosConfig` and an LLM key respectively, which would turn this
 * into an integration test instead of a fast unit test. Those paths
 * join when the full runner (docs/benchmark.md § Runner contract)
 * lands in Q4 2026.
 *
 * Value today:
 *  - Catches scanner un-wiring regressions (if JwtScanner disappears
 *    from the runtime path, SPX-BENCH-0001 fails).
 *  - Catches rule-removal regressions (if the
 *    `jwt-stored-localstorage` rule is deleted, the case fails).
 *  - Gives contributors an on-ramp to add new cases — the
 *    `_template` directory documents the shape.
 */

const __filename = fileURLToPath(import.meta.url);
// src/scanner/__tests__/ → repo root is 3 levels up.
const repoRoot = path.resolve(path.dirname(__filename), "..", "..", "..");
const CASES_DIR = path.join(repoRoot, "benchmark", "cases");

interface ExpectedFinding {
  file: string;
  rule_class: string;
  severity?: string;
  line_range?: [number, number];
}

interface CaseFile {
  id: string;
  title: string;
  cwe: string;
  severity: string;
  languages: string[];
  classes: string[];
  expected_findings: ExpectedFinding[];
}

/**
 * Scanners the v0.1 runner evaluates. When a new deterministic scanner
 * lands in the default runtime path (via `src/cli/commands/scan.ts`),
 * add it here so the benchmark sees it — or add it to
 * `BENCHMARK_EXCLUDED` below with a reason. The invariant test in
 * this file fails if a scanner is wired in scan.ts but appears in
 * neither list.
 */
const SCANNERS: Array<{
  name: string;
  make: () => { scan: (p: string) => Promise<{ findings: Vulnerability[] }> };
}> = [
  { name: "secrets", make: () => new SecretsScanner() },
  { name: "jwt", make: () => new JwtScanner() },
  { name: "headers", make: () => new HeadersScanner() },
  { name: "session", make: () => new SessionScanner() },
  { name: "business-logic", make: () => new BusinessLogicScanner() },
  { name: "iac", make: () => new IacScanner() },
  { name: "llm-security", make: () => new LlmSecurityScanner() },
  { name: "api-security", make: () => new ApiSecurityScanner() },
  { name: "cloud", make: () => new CloudSecurityScanner() },
  { name: "crypto", make: () => new CryptoScanner() },
  { name: "privacy", make: () => new PrivacyScanner() },
  { name: "race-conditions", make: () => new RaceConditionScanner() },
  { name: "redos", make: () => new RedosScanner() },
];

/**
 * Scanners instantiated in src/cli/commands/scan.ts but deliberately
 * NOT included in SCANNERS above. Adding a new scanner to scan.ts
 * forces a choice: include it in SCANNERS (so the benchmark catches
 * rule-removal regressions for it) or add it here with a reason.
 * The invariant test enforces that — preventing silent benchmark
 * coverage drift.
 *
 * Spirit identical to `KNOWN_EXPERIMENTAL` in wiring-invariant.test.ts.
 */
const BENCHMARK_EXCLUDED = new Set<string>([
  // Needs a MythosConfig argument; v0.1 runner is config-free.
  "PatternScanner",
  // Needs network (OSV API); v0.1 runner is offline and hermetic.
  "DepScanner",
]);

async function runScannersAgainst(projectPath: string): Promise<Vulnerability[]> {
  const all: Vulnerability[] = [];
  for (const { make } of SCANNERS) {
    const result = await make().scan(projectPath);
    all.push(...result.findings);
  }
  return all;
}

function normaliseFile(p: string): string {
  return p.replace(/\\/g, "/");
}

function listCaseDirs(): string[] {
  if (!fs.existsSync(CASES_DIR)) return [];
  return fs
    .readdirSync(CASES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^SPX-BENCH-\d+$/.test(d.name))
    .map((d) => d.name)
    .sort();
}

describe("Sphinx Benchmark v0.1 scaffold", () => {
  const caseIds = listCaseDirs();

  it("discovers at least one benchmark case", () => {
    expect(caseIds.length).toBeGreaterThanOrEqual(1);
  });

  it.each(caseIds)("case %s: every expected_finding is produced", async (caseId) => {
    const caseDir = path.join(CASES_DIR, caseId);
    const raw = fs.readFileSync(path.join(caseDir, "case.yml"), "utf8");
    const data = yaml.load(raw) as CaseFile;
    const vulnerableDir = path.join(caseDir, "vulnerable");

    expect(data.id).toBe(caseId);
    expect(fs.existsSync(vulnerableDir)).toBe(true);
    expect(Array.isArray(data.expected_findings)).toBe(true);
    expect(data.expected_findings.length).toBeGreaterThanOrEqual(1);

    // Scan from the case root so produced `file` paths match the
    // schema-specified form `vulnerable/<path>`. Scanners also walk
    // `safe/` — a finding there would be a false positive worth
    // surfacing, but for SPX-BENCH-0001 the safe fixture is clean.
    const produced = await runScannersAgainst(caseDir);

    for (const expected of data.expected_findings) {
      const expectedFile = normaliseFile(expected.file);
      const match = produced.find(
        (f) =>
          normaliseFile(f.location.file).endsWith(expectedFile) &&
          f.rule.includes(expected.rule_class)
      );
      if (!match) {
        const summary = produced
          .map((f) => `  ${normaliseFile(f.location.file)}:${f.location.line} rule=${f.rule}`)
          .join("\n");
        throw new Error(
          `Case ${data.id}: no finding matched expected file="${expectedFile}" rule_class="${expected.rule_class}".\nProduced ${produced.length} finding(s):\n${summary || "  (none)"}\n`
        );
      }
    }
  });
});

describe("Sphinx Benchmark v0.1 scanner-coverage invariant", () => {
  it("every scanner instantiated in scan.ts is in SCANNERS or BENCHMARK_EXCLUDED", () => {
    // Sister-invariant to wiring-invariant.test.ts. The wiring test
    // catches scanners declared in src/scanner/ that aren't wired
    // into any runtime entry point. This test catches the next
    // silent drift: scanners wired into scan.ts's default pipeline
    // that AREN'T being evaluated by the benchmark scaffold.
    //
    // Pre this commit, SCANNERS was a 5-entry hardcoded list and
    // any new scanner in scan.ts just … didn't run in the
    // benchmark. A future SPX-BENCH case expecting findings from
    // an unregistered scanner would fail cryptically at the
    // `every expected_finding is produced` assertion without any
    // hint that the root cause was SCANNERS, not the case.
    // Source of truth: src/core/run-scan.ts is where scanners get
    // instantiated on `mythos-agent scan` (and /api/scan) since the
    // runScan extraction (c4e90a4 / 203fa4c). Pre-refactor this was
    // scan.ts itself.
    const scanSrcPath = path.join(repoRoot, "src/core/run-scan.ts");
    const scanSrc = fs.readFileSync(scanSrcPath, "utf-8");

    const wired = new Set<string>();
    for (const m of scanSrc.matchAll(/\bnew\s+(\w+Scanner)\s*\(/g)) {
      wired.add(m[1]);
    }

    expect(wired.size).toBeGreaterThan(0);

    const inScaffold = new Set<string>();
    for (const { make } of SCANNERS) {
      inScaffold.add(make().constructor.name);
    }

    const unaccounted = [...wired].filter((c) => !inScaffold.has(c) && !BENCHMARK_EXCLUDED.has(c));

    if (unaccounted.length > 0) {
      throw new Error(
        `Scanner(s) are wired in src/core/run-scan.ts but missing from both SCANNERS and BENCHMARK_EXCLUDED:\n` +
          unaccounted.map((c) => `  - ${c}`).join("\n") +
          "\n\nEither:\n" +
          "  (a) add a `{ name, make: () => new Xxx() }` entry to SCANNERS in this file, or\n" +
          "  (b) add the class name to BENCHMARK_EXCLUDED with a reason.\n"
      );
    }
    expect(unaccounted).toEqual([]);
  });

  it("BENCHMARK_EXCLUDED entries are all actually wired in run-scan.ts (no stale)", () => {
    // Mirror of wiring-invariant's "allowlist entries are actually
    // declared" test. If a scanner is removed from run-scan.ts but
    // its BENCHMARK_EXCLUDED entry lingers, the next maintainer has
    // misleading context — remove it.
    const scanSrc = fs.readFileSync(path.join(repoRoot, "src/core/run-scan.ts"), "utf-8");
    const wired = new Set<string>();
    for (const m of scanSrc.matchAll(/\bnew\s+(\w+Scanner)\s*\(/g)) {
      wired.add(m[1]);
    }
    const stale = [...BENCHMARK_EXCLUDED].filter((c) => !wired.has(c));
    expect(
      stale,
      "Remove these from BENCHMARK_EXCLUDED — they're no longer wired in run-scan.ts"
    ).toEqual([]);
  });
});
