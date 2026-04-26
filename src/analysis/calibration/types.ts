/**
 * Types for the variants v2 calibration harness — sub-PR A3 of issue
 * #48 / Track A in docs/path-forward.md.
 *
 * Calibration validates the A1+A2 composition against the 2 / 5 caught
 * CVE Replay cases (semver CVE-2022-25883, follow-redirects
 * CVE-2024-28849). For each case it: loads the case JSON, looks up
 * A1's seed RootCausePattern, drives A2's `findAstPattern` against the
 * upstream vulnerable file, and asserts at least one match's line
 * range overlaps the case's `calibration_target.lines` band.
 *
 * If A3 produces 0 hits after a serious attempt at the AST matcher,
 * the kill criterion in docs/path-forward.md fires (2026-10-26): the
 * structured-root-cause approach also isn't enough, and the next bet
 * is Track C (differential fuzzing), not deeper Track A iteration.
 *
 * This module is deliberately offline (uses static fixtures committed
 * under __tests__/fixtures/), so it can run in regular CI without
 * network or git. The full agent-driven calibration (A3b) — actually
 * running variant-analyzer with LLM credit against live clones — is a
 * separate runner that the user dispatches when ready.
 */

/**
 * Subset of the CVE Replay case schema this module needs. Mirrors
 * `benchmarks/cve-replay/schema.json`; intentionally a partial type
 * so the harness ignores fields it doesn't use (rule_class, severity,
 * notes, etc.). Adding required fields here would couple the
 * calibration to a wider slice of the schema than necessary.
 */
export interface CalibrationCaseFile {
  ghsa_id: string;
  cve_id?: string;
  vulnerable_commit: string;
  calibration_target?: {
    file: string;
    lines: [number, number];
    note?: string;
  };
}

/**
 * Outcome of running calibration on a single case. `matched` is the
 * gate the kill criterion is measured against; `target` is echoed
 * back so callers can format human-readable scoreboards without
 * re-loading the case file.
 */
export interface CalibrationResult {
  ghsaId: string;
  cveId: string;
  matched: boolean;
  /** Number of AST matches the matcher returned (any line range). */
  totalMatches: number;
  /** Subset of matches whose line range overlaps the target band. */
  overlappingMatches: number;
  target: {
    file: string;
    lines: [number, number];
  };
  /**
   * If the seed corpus has no entry for this case's CVE, calibration
   * is skipped (not failed) — observational cases without seeds are
   * legitimate. The runner reports `matched: false, skipped: true`.
   */
  skipped?: boolean;
  skipReason?: string;
}
