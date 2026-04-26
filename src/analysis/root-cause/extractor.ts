import type Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig } from "../../types/index.js";
import { type LLMClient, createLLMClient } from "../../llm/index.js";
import type { CveInput, RootCausePattern } from "./types.js";
import { SEED_PATTERNS, getSeedPattern } from "./seed-patterns.js";

/**
 * Sub-PR A1 of variants v2 — see docs/path-forward.md Track A.
 *
 * The variant-hunt experiment proved that the prompt-only variants v1
 * approach can't reliably find variants on matched targets. The fix
 * isn't a better prompt; it's structured representation. This module
 * is the producer of that structured representation: it converts a
 * CVE description into a `RootCausePattern` that downstream layers
 * (A2's AST matcher, A3's calibration corpus) consume deterministically.
 *
 * Two-tier resolution:
 *
 *  1. **Seed lookup (sync, no LLM call).** The 5 CVEs in the existing
 *     CVE Replay corpus have hand-curated seed patterns in
 *     seed-patterns.ts. Those are the calibration ground truth — A3
 *     uses them as targets the AST matcher must hit, so they need to
 *     be reproducible across model swaps.
 *
 *  2. **LLM extraction (async, via the multi-model factory).** For
 *     non-seeded CVEs, the extractor builds an extraction prompt
 *     anchored on a few seed examples and asks the LLM for the same
 *     schema. Going through `createLLMClient` (matching PRs #44,
 *     #46, #47) means `provider: openai` users get an OpenAILLMClient
 *     and `provider: anthropic` (default) users get the Anthropic
 *     client — same multi-model behavior the rest of the agent layer
 *     already has.
 *
 * Single-shot, not agentic: the extraction takes a CVE description as
 * input and returns a JSON pattern as output. There's no codebase-
 * exploration loop and no tool use — that complexity belongs to A2's
 * matcher and the existing variant-analyzer's hunt loop, not to A1.
 */

const ROOT_CAUSE_SYSTEM = `You are a security pattern extractor. Given a CVE description, you produce a structured "root-cause pattern" that downstream tooling can match against arbitrary codebases.

A root-cause pattern has six fields:
  - bugClass: a short kebab-case label for the underlying mistake (e.g. "redos-static-template-regex", "jwt-algorithm-key-confusion"). Be specific — "redos" alone is not enough; the AST shape distinguishes static-template-built ReDoS from dynamic-regex ReDoS.
  - cwe: the canonical CWE id (e.g. "CWE-1333").
  - languages: ecosystems the pattern applies to (e.g. ["javascript", "typescript"]).
  - astShape: { kind, constraints }. "kind" is the top-level tree-sitter node kind (e.g. "regex_literal", "call_expression", "new_expression", "function_declaration"). "constraints" is a list of human-readable predicates over descendants — concrete enough to translate into an ast-grep-style query later.
  - dataFlow: { source, sink, propagation? }. "source" is where attacker-controlled data enters; "sink" is where it lands and triggers the bug; optional "propagation" describes intermediate steps.
  - summary: one-paragraph plain-English description of the mistake.

Rules:
  - Match the UNDERLYING MISTAKE, not the surface syntax. A regex literal with unbounded \\s* adjacent to a template interpolation slot is the same root cause as a RegExp constructor receiving a similarly-shaped string — but the astShape.kind is different, and the variant matcher needs to know which one applies.
  - Be specific about constraints. "Contains a regex" is too vague; "regex literal whose source contains an unbounded whitespace class adjacent to a \${} interpolation slot" is actionable.
  - Output ONLY valid JSON matching the schema. No commentary, no markdown fences, no explanation. The first character of your response must be '{'.`;

/**
 * The first 2 seed patterns are prepended to every extraction prompt
 * as concrete few-shot examples of the schema. Two is enough to anchor
 * the format without burning an unbounded amount of input tokens for
 * every call. The choice of which two is intentional: one is a static-
 * structure bug (lodash template injection) and one is a dynamic-flow
 * bug (path-to-regexp ReDoS), so the LLM sees both ends of the AST-
 * shape spectrum.
 */
const FEW_SHOT_INDICES = [0, 1] as const;

const MAX_TOKENS = 2048;

export class RootCauseExtractor {
  private client: LLMClient;

  constructor(
    private config: MythosConfig,
    client?: LLMClient | Anthropic
  ) {
    this.client = (client as LLMClient | undefined) ?? createLLMClient(config);
  }

  /**
   * Extract a root-cause pattern for a CVE. Tries the seed corpus
   * first (deterministic, no LLM call); falls back to LLM extraction.
   *
   * Returns `null` only if BOTH the seed lookup misses AND the LLM
   * call returns malformed output. A successful seed lookup never
   * touches the LLM.
   *
   * @param input - CVE id + description (required), plus optional
   *   CWE / code snippet / language hints.
   * @param options.skipSeed - bypass the seed corpus and force an LLM
   *   call. Used by the seed-regression test that re-extracts seeded
   *   CVEs from scratch and compares against the hand-curated truth.
   */
  async extract(
    input: CveInput,
    options?: { skipSeed?: boolean }
  ): Promise<RootCausePattern | null> {
    if (!options?.skipSeed) {
      const seed = getSeedPattern(input.id);
      if (seed) return seed;
    }

    const prompt = buildExtractionPrompt(input);
    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: MAX_TOKENS,
      system: ROOT_CAUSE_SYSTEM,
      messages: [{ role: "user", content: prompt }],
    });

    const text = response.content.find((b) => b.type === "text");
    if (!text || text.type !== "text") return null;

    return parsePattern(text.text, input.id);
  }
}

/**
 * Builds the extraction prompt for a CVE input. Module-level (not a
 * private method) so tests can pin the prompt shape directly without
 * constructing the class — matches the parseVariants pattern in
 * variant-analyzer.ts.
 */
export function buildExtractionPrompt(input: CveInput): string {
  const examples = FEW_SHOT_INDICES.map((i) => SEED_PATTERNS[i])
    .map((seed) => `Example — ${seed.cveId}:\n${JSON.stringify(seed, null, 2)}`)
    .join("\n\n");

  const codeSection = input.affectedCode
    ? `\n\nAffected code (from the vulnerable commit):\n${input.affectedCode}`
    : "";
  const cweSection = input.cwe ? `\nCWE: ${input.cwe}` : "";
  const langSection = input.language ? `\nPrimary language: ${input.language}` : "";

  return `${examples}

Now extract a root-cause pattern for this CVE.

CVE: ${input.id}${cweSection}${langSection}
Description: ${input.description}${codeSection}

Output JSON only.`;
}

/**
 * Parses an LLM response into a `RootCausePattern`. Module-level for
 * testability (mirrors `parseVariants` in variant-analyzer.ts) — tests
 * can hit the JSON-tolerance behavior without exercising the full
 * LLM round-trip.
 *
 * Behavior:
 *  - No JSON substring → returns `null`.
 *  - Malformed JSON → returns `null` without throwing. The caller
 *    treats null as "couldn't extract" and decides whether to retry,
 *    log, or fall through to a default.
 *  - Missing required fields → fall back to safe defaults (empty
 *    string, empty array, etc.) so partial outputs don't crash the
 *    pipeline. The caller can inspect `bugClass === ""` to detect
 *    a degenerate parse.
 */
export function parsePattern(text: string, cveId: string): RootCausePattern | null {
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) return null;

  let data: unknown;
  try {
    data = JSON.parse(jsonMatch[0]);
  } catch {
    return null;
  }
  if (typeof data !== "object" || data === null) return null;
  const obj = data as Record<string, unknown>;

  const astShapeRaw = (obj.astShape ?? {}) as Record<string, unknown>;
  const dataFlowRaw = (obj.dataFlow ?? {}) as Record<string, unknown>;

  return {
    cveId: typeof obj.cveId === "string" && obj.cveId ? obj.cveId : cveId,
    ghsaId: typeof obj.ghsaId === "string" ? obj.ghsaId : undefined,
    bugClass: typeof obj.bugClass === "string" ? obj.bugClass : "",
    cwe: typeof obj.cwe === "string" ? obj.cwe : "",
    languages: Array.isArray(obj.languages)
      ? obj.languages.filter((l): l is string => typeof l === "string")
      : [],
    astShape: {
      kind: typeof astShapeRaw.kind === "string" ? astShapeRaw.kind : "",
      constraints: Array.isArray(astShapeRaw.constraints)
        ? astShapeRaw.constraints.filter((c): c is string => typeof c === "string")
        : [],
    },
    dataFlow: {
      source: typeof dataFlowRaw.source === "string" ? dataFlowRaw.source : "",
      sink: typeof dataFlowRaw.sink === "string" ? dataFlowRaw.sink : "",
      propagation:
        typeof dataFlowRaw.propagation === "string" ? dataFlowRaw.propagation : undefined,
    },
    summary: typeof obj.summary === "string" ? obj.summary : "",
  };
}
