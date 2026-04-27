import type Anthropic from "@anthropic-ai/sdk";
import { type LLMClient, createLLMClient } from "../../llm/index.js";
import type { MythosConfig } from "../../types/index.js";
import { VariantAnalyzer, type CveInfo, type VariantMatch } from "../variant-analyzer.js";
import { getSeedPattern } from "../root-cause/seed-patterns.js";
import type { RootCausePattern } from "../root-cause/types.js";
import type { CalibrationCaseFile } from "./types.js";
import { wrapLLMClientWithLogging, type TurnRecord } from "./logging-client.js";

/**
 * Sub-PR A3b of variants v2 — the *agent-driven* calibration runner.
 *
 * Where A3a (`runner.ts` in this directory) is the deterministic
 * offline check (run A2's matcher with A1's seed against a static
 * fixture), A3b drives the full `VariantAnalyzer` agent loop against
 * a live-cloned upstream repo and observes whether the LLM, given
 * A1's structured seed pattern in the prompt, lands on a candidate
 * whose file/line range overlaps the case's `calibration_target`.
 *
 * Cost note: this module performs paid LLM calls (Anthropic by
 * default; OpenAI-compat via the multi-model factory). The harness
 * CLI wrapper in `benchmarks/variants-calibration/run.ts` is what
 * actually fires them. This module exposes the per-case loop as a
 * function so it stays testable with a mock client (no API cost in
 * CI) and so a future scheduled job could call it programmatically.
 *
 * Why pass `client?` rather than letting `VariantAnalyzer` build one
 * via `createLLMClient`: tests inject a scriptable mock; callers that
 * want the multi-model factory pass `undefined` and let the analyzer
 * resolve it. Same pattern as `RootCauseExtractor` (PR #50).
 *
 * Flow:
 *  1. Look up A1's seed pattern for the case (skip if missing).
 *  2. Build a `CveInfo` whose `rootCause` field carries the seed's
 *     structured shape — this is the channel by which A1's structured
 *     pattern reaches the LLM. The variant-analyzer system prompt
 *     already asks the model to "extract the ROOT CAUSE"; with a
 *     pre-extracted root cause in the prompt, it short-circuits to
 *     step 2 (search) and is nudged toward `find_ast_pattern` via
 *     the kind hint.
 *  3. Call `VariantAnalyzer.searchForVariants(cveInfo)` against the
 *     vulnerable-commit checkout.
 *  4. Compute calibration_target overlap on the returned variants.
 */

export interface AgentCalibrationOptions {
  /** Project path (typically a vulnerable-commit checkout). */
  projectPath: string;
  /** mythos-agent config (model, provider, apiKey, etc.). */
  config: MythosConfig;
  /** Inject a pre-built LLM client; tests use a scriptable mock. */
  client?: LLMClient | Anthropic;
  /**
   * Optional per-turn diagnostic logger. When set, the LLM client is
   * wrapped (see `logging-client.ts`) and `onTurn` fires after every
   * `messages.create` round-trip with the stop reason, tool calls,
   * text preview, and usage. The CLI harness uses this to write
   * `<ghsa>.turns.jsonl` alongside each result, so a 0-variants
   * outcome can be diagnosed (did the agent reach for
   * `find_ast_pattern`?) without re-running.
   */
  onTurn?: (record: TurnRecord) => void;
}

export interface AgentCalibrationResult {
  ghsaId: string;
  cveId: string;
  /** True if at least one variant overlaps the calibration_target band. */
  matched: boolean;
  /** Number of variants the agent returned (any line range). */
  variantsFound: number;
  /** Subset whose file/line overlaps the target. */
  overlappingVariants: number;
  /** Variants returned by the agent (full list, for output JSON). */
  variants: VariantMatch[];
  /** Echo target so callers can scoreboard without re-loading the case. */
  target: { file: string; lines: [number, number] };
  /** Wall-clock duration in milliseconds. */
  durationMs: number;
  /** Skip metadata (set when prerequisites aren't met). */
  skipped?: boolean;
  skipReason?: string;
  /** Captured error message if `searchForVariants` threw. */
  error?: string;
}

/**
 * Build a richer `CveInfo` than the OSV path would produce. The
 * `rootCause` field is the carrier for A1's structured seed pattern
 * — the variant-analyzer system prompt already references "root cause"
 * as a concept, so dropping the seed in here threads through the
 * existing prompt shape without modifying the analyzer's prompt.
 *
 * Module-level export so tests can pin the prompt-input shape without
 * standing up the full agent loop. The CLI calls this only once per
 * case; perf isn't a concern.
 */
export function buildCveInfoFromSeed(
  caseFile: CalibrationCaseFile,
  seed: RootCausePattern
): CveInfo {
  const constraintBullets = seed.astShape.constraints.map((c) => `  - ${c}`).join("\n");
  const flow =
    `${seed.dataFlow.source} → ${seed.dataFlow.sink}` +
    (seed.dataFlow.propagation ? `\n  via: ${seed.dataFlow.propagation}` : "");

  const rootCause = [
    `Bug class: ${seed.bugClass} (${seed.cwe})`,
    `Summary: ${seed.summary}`,
    "",
    `AST shape (use the find_ast_pattern tool with kind="${seed.astShape.kind}"):`,
    constraintBullets,
    "",
    `Data flow: ${flow}`,
  ].join("\n");

  return {
    id: caseFile.cve_id ?? caseFile.ghsa_id,
    description: seed.summary,
    severity: "high",
    cwe: seed.cwe,
    rootCause,
  };
}

export async function runAgentCalibration(
  caseFile: CalibrationCaseFile,
  opts: AgentCalibrationOptions
): Promise<AgentCalibrationResult> {
  const start = Date.now();
  const target = caseFile.calibration_target;
  const cveId = caseFile.cve_id ?? caseFile.ghsa_id;

  if (!target) {
    return {
      ghsaId: caseFile.ghsa_id,
      cveId,
      matched: false,
      variantsFound: 0,
      overlappingVariants: 0,
      variants: [],
      target: { file: "", lines: [0, 0] },
      durationMs: Date.now() - start,
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
      variantsFound: 0,
      overlappingVariants: 0,
      variants: [],
      target: { file: target.file, lines: target.lines },
      durationMs: Date.now() - start,
      skipped: true,
      skipReason: `no A1 seed pattern for ${cveId}`,
    };
  }

  const cveInfo = buildCveInfoFromSeed(caseFile, seed);

  // Resolve the client here (rather than inside VariantAnalyzer) so we
  // can wrap it with the per-turn logger when `onTurn` is set. Without
  // resolution at this layer, `wrapLLMClientWithLogging` would not see
  // a constructed client to delegate to.
  let resolvedClient: LLMClient | Anthropic | undefined = opts.client;
  if (opts.onTurn) {
    const base = (resolvedClient as LLMClient | undefined) ?? createLLMClient(opts.config);
    resolvedClient = wrapLLMClientWithLogging(base, opts.onTurn);
  }

  const analyzer = new VariantAnalyzer(opts.config, opts.projectPath, resolvedClient);

  let variants: VariantMatch[];
  try {
    variants = await analyzer.searchForVariants(cveInfo);
  } catch (err) {
    return {
      ghsaId: caseFile.ghsa_id,
      cveId,
      matched: false,
      variantsFound: 0,
      overlappingVariants: 0,
      variants: [],
      target: { file: target.file, lines: target.lines },
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  const overlapping = variants.filter((v) => overlapsTarget(v, target));

  return {
    ghsaId: caseFile.ghsa_id,
    cveId,
    matched: overlapping.length > 0,
    variantsFound: variants.length,
    overlappingVariants: overlapping.length,
    variants,
    target: { file: target.file, lines: target.lines },
    durationMs: Date.now() - start,
  };
}

/**
 * Overlap predicate: a variant counts as hitting the target band if
 * its `file` ends with the target's file path AND its single `line`
 * is within `[startLine, endLine]` inclusive. The variant-analyzer
 * returns a single `line` (not a range) per variant, so the overlap
 * check is line-against-band rather than range-against-range like
 * A3a's `runner.ts`.
 */
function overlapsTarget(
  variant: VariantMatch,
  target: { file: string; lines: [number, number] }
): boolean {
  const variantFile = variant.file.replace(/\\/g, "/");
  const targetFile = target.file.replace(/\\/g, "/");
  if (!variantFile.endsWith(targetFile)) return false;
  const [start, end] = target.lines;
  return variant.line >= start && variant.line <= end;
}
