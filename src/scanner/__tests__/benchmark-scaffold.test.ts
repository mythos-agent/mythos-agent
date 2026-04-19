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
 * `SphinxConfig` and an LLM key respectively, which would turn this
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
 * add it here so the benchmark sees it.
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
];

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
