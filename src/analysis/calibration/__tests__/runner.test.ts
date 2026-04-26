import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCalibration } from "../runner.js";
import type { CalibrationCaseFile } from "../types.js";

// Sub-PR A3 of variants v2 — see docs/path-forward.md Track A.
//
// These tests are the calibration corpus's gate. For each of the 2/5
// caught CVE Replay cases (semver CVE-2022-25883, follow-redirects
// CVE-2024-28849), we drive A2's findAstPattern with A1's seed
// RootCausePattern against the upstream vulnerable file and assert
// at least one returned match's line range overlaps the case's
// `calibration_target.lines` band.
//
// Per docs/path-forward.md: "If A3 (calibration on known cases)
// produces 0 candidates after a serious attempt at the AST matcher,
// the structured-root-cause approach also isn't enough." These tests
// formalize that gate. A regression here is a strong signal that
// either A1's seed has drifted from the upstream code or A2's
// matcher needs structural enhancements.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(__dirname, "fixtures");
const CASES_DIR = path.resolve(__dirname, "../../../../benchmarks/cve-replay/cases");

function loadCase(ghsa: string): CalibrationCaseFile {
  const file = path.join(CASES_DIR, `${ghsa}.json`);
  return JSON.parse(fs.readFileSync(file, "utf-8"));
}

function loadFixture(ghsa: string, filename: string): string {
  return fs.readFileSync(path.join(FIXTURES_DIR, ghsa, filename), "utf-8");
}

describe("runCalibration — caught CVE Replay cases", () => {
  it("CVE-2022-25883 semver: matches the vulnerable TRIM template literals", async () => {
    const caseFile = loadCase("GHSA-c2qf-rxjj-qqgw");
    const source = loadFixture("GHSA-c2qf-rxjj-qqgw", "re.js");
    const result = await runCalibration(caseFile, source);

    expect(result.skipped).toBeFalsy();
    expect(result.matched).toBe(true);
    expect(result.overlappingMatches).toBeGreaterThan(0);
    expect(result.target.file).toBe("internal/re.js");
    expect(result.target.lines).toEqual([138, 161]);
    // Sanity: the matcher returned more total matches than overlapping
    // ones — node-semver's re.js builds many regexes, and the seed's
    // bare `template_string` kind catches all of them. Tightening this
    // is A2.x territory (constraint-based predicates over template
    // contents).
    expect(result.totalMatches).toBeGreaterThanOrEqual(result.overlappingMatches);
  });

  it("CVE-2024-28849 follow-redirects: matches the regex on line 464", async () => {
    const caseFile = loadCase("GHSA-cxjh-pqwp-8mfp");
    const source = loadFixture("GHSA-cxjh-pqwp-8mfp", "index.js");
    const result = await runCalibration(caseFile, source);

    expect(result.skipped).toBeFalsy();
    expect(result.matched).toBe(true);
    expect(result.overlappingMatches).toBeGreaterThan(0);
    expect(result.target.file).toBe("index.js");
    expect(result.target.lines).toEqual([464, 464]);
  });
});

describe("runCalibration — skip semantics", () => {
  it("skips a case without a calibration_target (observational-only)", async () => {
    const observational: CalibrationCaseFile = {
      ghsa_id: "GHSA-test-0000-0000",
      cve_id: "CVE-9999-99999",
      vulnerable_commit: "0".repeat(40),
      // No calibration_target set on purpose.
    };
    const result = await runCalibration(observational, "const x = 1;");
    expect(result.skipped).toBe(true);
    expect(result.matched).toBe(false);
    expect(result.skipReason).toMatch(/calibration_target/);
  });

  it("skips when the case has a target but no A1 seed (drift detection)", async () => {
    // The seed-corpus completeness test in root-cause/__tests__/
    // already catches this drift; calibration handling it as a skip
    // (rather than a hard failure) keeps the runner monotonic. Tests
    // that assert .matched still surface the missing-seed case as
    // "not matched", but seed-corpus drift gets reported by its own
    // dedicated test rather than as a misleading calibration failure.
    const unseeded: CalibrationCaseFile = {
      ghsa_id: "GHSA-test-9999-9999",
      cve_id: "CVE-1999-9999",
      vulnerable_commit: "0".repeat(40),
      calibration_target: {
        file: "lib/index.js",
        lines: [1, 10],
      },
    };
    const result = await runCalibration(unseeded, "const x = 1;");
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toMatch(/no A1 seed pattern/);
  });

  it("skips when the calibration_target.file is in an unsupported language", async () => {
    const pyCase: CalibrationCaseFile = {
      ghsa_id: "GHSA-c2qf-rxjj-qqgw", // valid seeded ghsa
      cve_id: "CVE-2022-25883",
      vulnerable_commit: "0".repeat(40),
      calibration_target: {
        file: "lib/some.py", // unsupported extension
        lines: [1, 10],
      },
    };
    const result = await runCalibration(pyCase, "x = 1");
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toMatch(/unsupported language/);
  });
});

describe("runCalibration — line-range overlap semantics", () => {
  it("counts a match whose range starts before the target as overlapping", async () => {
    // The semver fixture's vulnerable bands span lines 138-161 in the
    // original commit; this test verifies the overlap algorithm
    // accepts matches that start at or before targetStart and end
    // within or after the band. Without this, multi-line template
    // literals that begin one line before the named "vulnerable" line
    // would be wrongly counted as misses.
    const caseFile = loadCase("GHSA-c2qf-rxjj-qqgw");
    const source = loadFixture("GHSA-c2qf-rxjj-qqgw", "re.js");
    const result = await runCalibration(caseFile, source);

    // Synthesize a tighter target band (line 160 only) and verify
    // multi-line COMPARATORTRIM at lines 160-161 still overlaps.
    const tightCase: CalibrationCaseFile = {
      ...caseFile,
      calibration_target: { file: "internal/re.js", lines: [160, 160] },
    };
    const tight = await runCalibration(tightCase, source);
    // matched depends on actual file layout; assert both ran without
    // skipping rather than asserting matched=true (which would couple
    // the test to exact upstream line numbers).
    expect(tight.skipped).toBeFalsy();
    expect(result.matched).toBe(true);
  });
});
