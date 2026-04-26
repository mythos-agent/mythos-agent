/**
 * Types for the root-cause-pattern extraction layer (sub-PR A1 of
 * variants v2 — see docs/path-forward.md Track A).
 *
 * The variant-hunt experiment (docs/research/2026-04-26-variant-hunt-
 * experiment.md) showed that prompt-only variant search can't reliably
 * find variants on matched targets even with a frontier model. The fix
 * is structured representation: a CVE is reduced to a **pattern** —
 * bug class + AST shape + data-flow direction + applicable languages —
 * that downstream layers (A2's AST matcher, A3's calibration corpus)
 * can match against deterministically.
 *
 * Field-by-field rationale:
 *
 *  - `bugClass` is the project-internal label used to bucket variants.
 *    It is intentionally NOT tied to scanner rule ids (those are
 *    detector-output, not detector-input) and NOT tied to CWE
 *    (CWE buckets are too coarse: CVE-2022-25883 and CVE-2024-45296
 *    are both CWE-1333 ReDoS but their AST shapes are completely
 *    different — one is a static template-built regex, the other is
 *    a dynamic regex constructed from caller input).
 *
 *  - `cwe` is included for cross-referencing with external corpora
 *    (NVD, OSV, MITRE). It's a canonical id, not a freeform string.
 *
 *  - `astShape` is the structured handle that A2's AST matcher will
 *    consume. `kind` names the top-level tree-sitter node kind
 *    (e.g. `regex_literal`, `call_expression`); `constraints` is a
 *    list of human-readable predicates over descendants. Keeping it
 *    semi-structured (kind + prose constraints) instead of fully
 *    formalized (e.g. ast-grep YAML) is deliberate for A1: the goal
 *    is to validate the *representation*, not commit to a query
 *    DSL before A2 picks one.
 *
 *  - `dataFlow.source → dataFlow.sink` describes WHERE the
 *    attacker-controlled value enters and WHERE it lands. This is
 *    the discriminator the variant matcher uses to filter "looks
 *    like the AST shape but is benign" matches (e.g. a regex
 *    literal with `\\s*` adjacent to interpolation is only
 *    interesting if the interpolated value is user-controlled).
 *
 *  - `languages` is a list of ecosystem identifiers
 *    (`javascript`, `python`, `go`, `java`, `rust`, etc.). Most
 *    seed patterns are JS/TS only because the CVE Replay corpus is
 *    npm-only today. Multi-language seeds will land when the corpus
 *    expands beyond Track A's initial scope.
 */
export interface RootCausePattern {
  /** CVE identifier in canonical form (`CVE-YYYY-NNNNN`). */
  cveId: string;
  /** GHSA identifier when available; some CVEs predate GHSA. */
  ghsaId?: string;
  /** Project-internal bug-class label; see file-level rationale. */
  bugClass: string;
  /** CWE identifier (e.g. `CWE-1333`). */
  cwe: string;
  /** Ecosystem identifiers the pattern applies to. */
  languages: string[];
  /** Structural handle for A2's AST matcher. */
  astShape: AstShape;
  /** Source → sink description of attacker-controlled data flow. */
  dataFlow: DataFlow;
  /** One-paragraph human-readable summary of the mistake. */
  summary: string;
}

export interface AstShape {
  /** Top-level tree-sitter node kind. */
  kind: string;
  /** Human-readable predicates over descendants of `kind`. */
  constraints: string[];
}

export interface DataFlow {
  /** Where attacker-controlled data enters (e.g. `request body field X`). */
  source: string;
  /** Where it lands and triggers the bug (e.g. `Function() constructor`). */
  sink: string;
  /** Optional intermediate steps between source and sink. */
  propagation?: string;
}

/**
 * Input for `RootCauseExtractor.extract` when the caller already has
 * CVE metadata (e.g. from `VariantAnalyzer.fetchCveInfo` or from a
 * benchmarks/cve-replay case file). Kept separate from the existing
 * `CveInfo` in variant-analyzer.ts because that one is shaped for the
 * variant search prompt, not for pattern extraction; merging them
 * would couple two evolving prompt surfaces.
 */
export interface CveInput {
  /** CVE id (`CVE-YYYY-NNNNN`) or GHSA id; both are accepted. */
  id: string;
  /** OSV/NVD-style summary or freeform description. */
  description: string;
  /** CWE id when known; helps the extractor short-circuit ambiguity. */
  cwe?: string;
  /** Optional code snippet from the vulnerable commit. */
  affectedCode?: string;
  /** Default language to anchor the extraction. */
  language?: string;
}
