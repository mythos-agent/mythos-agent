/**
 * System-prompt variants for the fix-A isolation experiment.
 *
 * The 2026-05-12 Bundle A+C run regressed qwen-max from 2/8 to 0/8: the
 * "## Workflow — REQUIRED" directive (fix A) universalized the 1-turn
 * give-up it was meant to eliminate. This module supplies three prompt
 * arms so a calibration run can attribute the regression to a specific
 * feature of that directive — the verbatim `variants: []` give-up token
 * or the numbered procedural list. See
 * docs/superpowers/specs/2026-05-19-qwen-fix-a-isolation-design.md.
 */

export type PromptVariant = "control" | "variant-a" | "variant-b";

// Everything up to and including the "## Key Insight" paragraph. The
// workflow directive (when present) is spliced in here, immediately
// before "## Output Format" — the same slot the 2026-05-12 fix-A
// directive used. Ends with a blank line so concatenation with either
// a directive or BASE_TAIL leaves exactly one blank line.
const BASE_HEAD = `You are a variant analysis engine, inspired by Google's Big Sleep project. Given a known CVE (vulnerability), you find STRUCTURALLY SIMILAR but SYNTACTICALLY DIFFERENT code in the target codebase.

## How Variant Analysis Works

1. Extract the ROOT CAUSE of the known vulnerability (not the surface pattern)
   - Example: CVE describes "buffer overflow in URL parser" → root cause is "length not checked before copy into fixed-size buffer"
2. Search the codebase for code that shares the SAME ROOT CAUSE
   - Same type of mistake, different function, different variable names
3. Rate similarity: high (same root cause + same data flow), medium (same root cause, different context), low (similar pattern, unclear if exploitable)

## Key Insight
Don't match surface syntax. Match the UNDERLYING MISTAKE. A buffer overflow in a URL parser and a buffer overflow in a JSON parser have the same root cause pattern even though the code looks completely different.

`;

// The "## Output Format" section onwards — unchanged from the original
// VARIANT_SYSTEM. Note this section already contains one `variants: []`
// occurrence inside the *schema example*; that is shared by all arms
// and is NOT what variant-a removes (variant-a removes only the
// give-up-directive occurrences).
const BASE_TAIL = `## Output Format

You MUST respond with a single JSON object and NOTHING ELSE. No markdown
headers, no prose explanation outside JSON fields, no code fences (no
\`\`\`json wrapper). The first character of your response MUST be '{' and
the last character MUST be '}'. Schema:

{
  "rootCauseAnalysis": "Description of the root cause pattern extracted from the CVE",
  "variants": [
    {
      "file": "src/parser.ts",
      "line": 42,
      "code": "the matching code snippet",
      "similarity": "high",
      "explanation": "This code has the same root cause: user-controlled length passed to buffer allocation without bounds check",
      "rootCauseMatch": "Unchecked length → buffer allocation"
    }
  ]
}

If you find no variants, respond with: {"rootCauseAnalysis": "...", "variants": []}.
Do not respond with prose explaining why you found nothing — the empty
array IS the explanation. The harness parses your output as JSON, and
prose responses produce a 0-variants result that is indistinguishable
from a clean miss.`;

// variant-a: the full 2026-05-12 fix-A numbered list, with the two
// verbatim `variants: []` give-up tokens replaced by neutral phrasing.
// Tests the negative-example-prime hypothesis (H-prime).
const DIRECTIVE_A = `## Workflow — REQUIRED

1. Identify the root cause from the CVE (one sentence in \`rootCauseAnalysis\`).
2. Call \`find_ast_pattern\` (or \`search_code\` if the AST kind is unclear) AT LEAST ONCE to find candidate sites in the codebase.
3. Only after a tool call has returned, emit your final JSON answer.

A result with no findings is valid — but only after step 2. Reporting no findings without first calling a search tool is treated as a failed run, not a genuine "no variants found" result. Identifying the root cause is step 1; mechanically searching for instances of it is step 2. Do NOT skip step 2.

`;

// variant-b: a single imperative sentence — no numbered list, no
// give-up token. Tests the procedural-list hypothesis (H-list).
const DIRECTIVE_B = `## Workflow — REQUIRED

Before emitting your final JSON answer you MUST call \`find_ast_pattern\` or \`search_code\` at least once to search the codebase; a final answer produced without any preceding search-tool call is treated as a failed run.

`;

const DIRECTIVES: Record<PromptVariant, string> = {
  control: "",
  "variant-a": DIRECTIVE_A,
  "variant-b": DIRECTIVE_B,
};

/**
 * Compose the variant-analysis system prompt for the given arm.
 * `control` returns the original prompt unchanged.
 */
export function buildVariantSystem(variant: PromptVariant): string {
  return BASE_HEAD + DIRECTIVES[variant] + BASE_TAIL;
}

/**
 * Resolve the `MYTHOS_VARIANT_PROMPT` env value to a PromptVariant.
 * Unset or empty → `control`. An unrecognized value throws, so a typo
 * fails loud instead of silently running the control arm.
 */
export function resolvePromptVariant(raw: string | undefined): PromptVariant {
  if (raw === undefined || raw === "") return "control";
  if (raw === "control" || raw === "variant-a" || raw === "variant-b") {
    return raw;
  }
  throw new Error(
    `Invalid MYTHOS_VARIANT_PROMPT="${raw}". Valid values: control, variant-a, variant-b (or unset for control).`
  );
}
