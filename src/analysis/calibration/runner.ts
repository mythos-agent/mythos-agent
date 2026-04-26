import { findAstPattern, inferLanguage } from "../ast-matcher/index.js";
import { getSeedPattern } from "../root-cause/seed-patterns.js";
import type { CalibrationCaseFile, CalibrationResult } from "./types.js";

/**
 * Calibration runner for sub-PR A3 (variants v2). Given a CVE Replay
 * case + the source of the vulnerable file at the case's
 * `vulnerable_commit`, drive A2's matcher with A1's seed pattern and
 * report whether any match overlaps the `calibration_target` line
 * band.
 *
 * Two-stage skip semantics:
 *
 *  - **No `calibration_target` on the case** → not a calibration
 *    case at all (most cases are observational-only). Returns
 *    `skipped: true`. Tests treat this as a no-op.
 *  - **Case has a target but no seed pattern** → the seed corpus
 *    hasn't been authored yet for this CVE. Returns `skipped: true`
 *    with a reason. The seed-corpus completeness test in
 *    src/analysis/root-cause/__tests__/root-cause.test.ts already
 *    catches this drift; we surface it as a calibration-skip rather
 *    than a hard failure to keep the calibration runner monotonic
 *    (a missing seed is an A1 problem, not an A3 design failure).
 *
 * Hit / miss is measured by line-range OVERLAP between any returned
 * match and the target band. A match at line 138 inside a target
 * band of [138, 161] counts; a match at line 137 doesn't. Overlap
 * (not exact match) because a match's startLine might be one line
 * earlier than the target's start when the upstream file's vulnerable
 * pattern spans multiple lines.
 *
 * Why the runner takes `source` rather than reading the file: the
 * test layer commits the fixture under __tests__/fixtures/ and reads
 * it; the runner stays IO-free so it composes with live-clone
 * harnesses (A3b) and benchmark scripts the same way.
 */
export async function runCalibration(
  caseFile: CalibrationCaseFile,
  source: string
): Promise<CalibrationResult> {
  const target = caseFile.calibration_target;
  const cveId = caseFile.cve_id ?? caseFile.ghsa_id;

  if (!target) {
    return {
      ghsaId: caseFile.ghsa_id,
      cveId,
      matched: false,
      totalMatches: 0,
      overlappingMatches: 0,
      target: { file: "", lines: [0, 0] },
      skipped: true,
      skipReason: "case has no calibration_target",
    };
  }

  const seed = getSeedPattern(caseFile.ghsa_id) ?? getSeedPattern(cveId);
  if (!seed) {
    return {
      ghsaId: caseFile.ghsa_id,
      cveId,
      matched: false,
      totalMatches: 0,
      overlappingMatches: 0,
      target: { file: target.file, lines: target.lines },
      skipped: true,
      skipReason: `no A1 seed pattern for ${cveId}`,
    };
  }

  const language = inferLanguage(target.file);
  if (!language) {
    return {
      ghsaId: caseFile.ghsa_id,
      cveId,
      matched: false,
      totalMatches: 0,
      overlappingMatches: 0,
      target: { file: target.file, lines: target.lines },
      skipped: true,
      skipReason: `unsupported language for file ${target.file}`,
    };
  }

  const matches = await findAstPattern({
    kind: seed.astShape.kind,
    source,
    language,
  });

  const [targetStart, targetEnd] = target.lines;
  const overlapping = matches.filter((m) => {
    // Line-range overlap, inclusive on both ends. A match counts if
    // its line range intersects the target band at any point.
    return m.startLine <= targetEnd && m.endLine >= targetStart;
  });

  return {
    ghsaId: caseFile.ghsa_id,
    cveId,
    matched: overlapping.length > 0,
    totalMatches: matches.length,
    overlappingMatches: overlapping.length,
    target: { file: target.file, lines: target.lines },
  };
}
