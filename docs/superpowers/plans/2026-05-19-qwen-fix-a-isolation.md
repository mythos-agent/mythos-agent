# qwen-max fix-A Isolation Experiment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the variant-analysis system prompt selectable at runtime among three arms (`control`, `variant-a`, `variant-b`) via the `MYTHOS_VARIANT_PROMPT` environment variable, so a qwen-max calibration run can attribute the 2026-05-12 fix-A regression to a specific feature of the directive.

**Architecture:** A new focused module `src/analysis/variant-prompt.ts` holds the prompt base text, the three directive variants, and two pure functions — `buildVariantSystem(variant)` and `resolvePromptVariant(raw)`. `variant-analyzer.ts` stops defining the prompt inline; instead it resolves the variant from the environment once at module load, builds the prompt, and logs the active variant to stderr. No harness (`run.ts`) changes — the env var is read directly, matching the existing `MYTHOS_BASE_URL` pattern.

**Tech Stack:** TypeScript (ESM, `.js` import extensions), vitest.

> **Deviation from spec:** the design's "Concrete edits" section said "All in `src/analysis/variant-analyzer.ts`." This plan instead puts the prompt machinery in a new `src/analysis/variant-prompt.ts`. Reason: `variant-analyzer.ts` is already 491 lines; a separate module keeps the prompt logic focused and unit-testable in isolation without constructing the analyzer. The behavior and prompt text are exactly as the spec specifies.

---

### Task 1: Create the `variant-prompt` module

**Files:**
- Create: `src/analysis/variant-prompt.ts`
- Test: `src/analysis/__tests__/variant-prompt.test.ts`

- [ ] **Step 1: Write the failing test**

Create `src/analysis/__tests__/variant-prompt.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import {
  buildVariantSystem,
  resolvePromptVariant,
} from "../variant-prompt.js";

// The fix-A isolation experiment (docs/research/2026-05-19-qwen-fix-a-isolation.md)
// needs three system-prompt arms. These tests pin the structural
// differences the experiment depends on: control has no workflow
// directive, variant-a keeps the numbered list but drops the verbatim
// `variants: []` give-up token, variant-b is a single sentence with no
// list. All three must share the same base prompt.

describe("buildVariantSystem", () => {
  it("control has no workflow directive but keeps the base sections", () => {
    const p = buildVariantSystem("control");
    expect(p).not.toContain("## Workflow — REQUIRED");
    expect(p).toContain("## How Variant Analysis Works");
    expect(p).toContain("## Output Format");
  });

  it("variant-a keeps the numbered workflow list", () => {
    const p = buildVariantSystem("variant-a");
    expect(p).toContain("## Workflow — REQUIRED");
    expect(p).toContain("1. Identify the root cause");
    expect(p).toContain("2. Call `find_ast_pattern`");
    expect(p).toContain("3. Only after a tool call has returned");
  });

  it("variant-a drops the verbatim `variants: []` give-up token", () => {
    const p = buildVariantSystem("variant-a");
    // The 2026-05-12 full-A directive said: Emitting `variants: []`
    // without calling any search tool ... — variant-a must NOT.
    expect(p).not.toContain("Emitting `variants: []`");
    expect(p).not.toContain("An empty `variants` array");
    expect(p).toContain("A result with no findings is valid");
  });

  it("variant-b has the workflow directive but no numbered list", () => {
    const p = buildVariantSystem("variant-b");
    expect(p).toContain("## Workflow — REQUIRED");
    expect(p).toContain("you MUST call `find_ast_pattern`");
    expect(p).not.toContain("1. Identify the root cause");
    expect(p).not.toContain("Emitting `variants: []`");
  });

  it("all three arms share the same base head and tail", () => {
    const arms = [
      buildVariantSystem("control"),
      buildVariantSystem("variant-a"),
      buildVariantSystem("variant-b"),
    ];
    for (const p of arms) {
      expect(p.startsWith("You are a variant analysis engine,")).toBe(true);
      expect(p.endsWith("indistinguishable\nfrom a clean miss.")).toBe(true);
    }
  });
});

describe("resolvePromptVariant", () => {
  it("treats unset and empty string as control", () => {
    expect(resolvePromptVariant(undefined)).toBe("control");
    expect(resolvePromptVariant("")).toBe("control");
  });

  it("passes through each recognized variant", () => {
    expect(resolvePromptVariant("control")).toBe("control");
    expect(resolvePromptVariant("variant-a")).toBe("variant-a");
    expect(resolvePromptVariant("variant-b")).toBe("variant-b");
  });

  it("throws on an unrecognized value, naming the bad value", () => {
    expect(() => resolvePromptVariant("varient-a")).toThrow(/varient-a/);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/analysis/__tests__/variant-prompt.test.ts`
Expected: FAIL — `Failed to resolve import "../variant-prompt.js"` (the module does not exist yet).

- [ ] **Step 3: Create the `variant-prompt.ts` module**

Create `src/analysis/variant-prompt.ts` with exactly this content:

```typescript
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/analysis/__tests__/variant-prompt.test.ts`
Expected: PASS — all 8 tests green.

> If the `endsWith` assertion fails, check that `BASE_TAIL` ends with the exact two-line break `indistinguishable\nfrom a clean miss.` as in the original `VARIANT_SYSTEM`. Do not change the prompt wording to satisfy the test — fix the test's expected string to match the real prompt.

- [ ] **Step 5: Format the new files**

Run: `npx prettier --write src/analysis/variant-prompt.ts src/analysis/__tests__/variant-prompt.test.ts`
Expected: both files reported as written (or already formatted).

> Do NOT run `npm run format` — it reformats all of `src/` and pollutes the working tree. Only the two files above.

- [ ] **Step 6: Commit**

```bash
git add src/analysis/variant-prompt.ts src/analysis/__tests__/variant-prompt.test.ts
git commit --signoff -m "feat(variants): prompt-variant module for fix-A isolation

Add src/analysis/variant-prompt.ts: PromptVariant type, the three
system-prompt arms (control / variant-a / variant-b), buildVariantSystem,
and resolvePromptVariant. variant-a keeps the 2026-05-12 fix-A numbered
list but drops the verbatim \`variants: []\` give-up token; variant-b is a
single imperative sentence. Pure functions, unit-tested; not yet wired
into variant-analyzer.ts.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Wire the env-var selection into `variant-analyzer.ts`

**Files:**
- Modify: `src/analysis/variant-analyzer.ts:1-4` (imports) and `:26-64` (replace the inline `VARIANT_SYSTEM` const)

**Context:** `variant-analyzer.ts` currently defines `VARIANT_SYSTEM` as a 39-line inline template literal (lines 26-64) and uses it at two `messages.create` call sites (`autoScan` and `searchForVariants`, both `system: VARIANT_SYSTEM`). This task replaces the inline literal with a value computed from `variant-prompt.ts` at module load. The const name `VARIANT_SYSTEM` and both call sites are kept exactly as-is — only how the const is produced changes.

- [ ] **Step 1: Add the import**

In `src/analysis/variant-analyzer.ts`, after the existing import block (currently lines 1-4), add a fourth import line so the import block reads:

```typescript
import type Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig, Vulnerability, Severity } from "../types/index.js";
import { type LLMClient, createLLMClient } from "../llm/index.js";
import { createAgentTools, executeToolCall } from "../agent/tools.js";
import { buildVariantSystem, resolvePromptVariant } from "./variant-prompt.js";
```

- [ ] **Step 2: Replace the inline `VARIANT_SYSTEM` const**

Delete the entire inline `const VARIANT_SYSTEM = \`...\`;` block (currently lines 26-64, starting `const VARIANT_SYSTEM = \`You are a variant analysis engine,` and ending `from a clean miss.\`;`) and replace it with:

```typescript
// The active system prompt is selected at module load from the
// MYTHOS_VARIANT_PROMPT env var (unset → "control"). This drives the
// fix-A isolation experiment — see
// docs/research/2026-05-19-qwen-fix-a-isolation.md. The resolved arm is
// logged to stderr so each calibration run records which prompt it used.
const ACTIVE_PROMPT_VARIANT = resolvePromptVariant(
  process.env.MYTHOS_VARIANT_PROMPT
);
const VARIANT_SYSTEM = buildVariantSystem(ACTIVE_PROMPT_VARIANT);
process.stderr.write(
  `[variant-analyzer] prompt variant: ${ACTIVE_PROMPT_VARIANT}\n`
);
```

Leave the two `system: VARIANT_SYSTEM` call sites and everything else in the file untouched.

- [ ] **Step 3: Run the full test suite**

Run: `npm test`
Expected: PASS — all tests green, including the existing `src/analysis/__tests__/variant-analyzer.test.ts` (which imports this module; a broken import or a load-time throw would fail every test in that file) and the new `variant-prompt.test.ts`.

- [ ] **Step 4: Run the type-checker**

Run: `npm run typecheck`
Expected: exit 0, no errors.

> Pre-existing note: `src/agent/tools.ts` may show an LSP hint about an unused `projectPath` parameter. That is pre-existing on `main` and not flagged by `npm run typecheck` — ignore it; it is out of scope.

- [ ] **Step 5: Verify the env var is actually read end-to-end**

Run: `npm run build`
Expected: exit 0.

Run: `MYTHOS_VARIANT_PROMPT=variant-b node -e "import('./dist/analysis/variant-analyzer.js').then(() => {})"`
Expected: stderr prints `[variant-analyzer] prompt variant: variant-b`.

Run: `node -e "import('./dist/analysis/variant-analyzer.js').then(() => {})"`
Expected: stderr prints `[variant-analyzer] prompt variant: control` (unset → control).

Run: `MYTHOS_VARIANT_PROMPT=bogus node -e "import('./dist/analysis/variant-analyzer.js').then(() => {}).catch(e => { console.error(e.message); process.exit(1); })"`
Expected: stderr prints the `Invalid MYTHOS_VARIANT_PROMPT="bogus"` error and exits non-zero.

> If `npm run build` is not defined or the `dist/` path differs, substitute the project's build output path. The point of this step is one positive, one default, and one error case proving the env var reaches `resolvePromptVariant`.

- [ ] **Step 6: Format the modified file**

Run: `npx prettier --write src/analysis/variant-analyzer.ts`
Expected: file reported as written (or already formatted).

> Do NOT run `npm run format`.

- [ ] **Step 7: Commit**

```bash
git add src/analysis/variant-analyzer.ts
git commit --signoff -m "feat(variants): select system prompt via MYTHOS_VARIANT_PROMPT

variant-analyzer.ts no longer defines the system prompt inline; it
resolves the arm from MYTHOS_VARIANT_PROMPT at module load via
variant-prompt.ts, builds the prompt, and logs the active arm to
stderr. Unset → control (unchanged behavior). Enables the fix-A
isolation calibration run without touching the benchmark harness.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Run the calibration and write up the result

**Files:**
- Create: `docs/research/2026-05-19-qwen-fix-a-isolation.md`

**Context:** This task is gated on the user running the harness — it needs `DASHSCOPE_API_KEY`, which only the user has, in their Git Bash window. The implementer must NOT attempt to run the harness or ask for the key.

- [ ] **Step 1: Hand the harness command to the user**

Post this block for the user to run in their Git Bash window (with `DASHSCOPE_API_KEY` already exported):

```bash
for v in control variant-a variant-b; do
  for i in 1 2 3 4; do
    MYTHOS_VARIANT_PROMPT=$v npm run benchmark:variants-calibration -- \
      --provider openai --model qwen-max \
      --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
      --results-subdir "2026-05-19-fixa-$v-round$i" \
      --log-turns
  done
done
```

Then STOP and wait. Do not proceed to Step 2 until the user confirms the 12 result directories exist under `benchmarks/variants-calibration/results/2026-05-19-fixa-{control,variant-a,variant-b}-round{1..4}/`.

- [ ] **Step 2: Analyze the results**

For each of the 12 `summary.json` files, record `matched` per case. For each of the 24 `*.turns.jsonl` files, record turn-1 `stopReason`, whether `toolCalls` is non-empty, and (if a tool was called) the `kind`/`text_predicates`. Build a per-arm hit table and a per-arm "turn-1 tool-call rate" — the latter is the primary signal (tool use recovered vs. mode A persists).

- [ ] **Step 3: Write `docs/research/2026-05-19-qwen-fix-a-isolation.md`**

Mirror the structure of `docs/research/2026-05-12-qwen-prompt-engineering.md`: TL;DR → why this writeup exists → hypothesis (H5, with the decision table from the spec) → methodology (note the `MYTHOS_VARIANT_PROMPT` variable and the commit SHA) → runs (per-arm table) → attribution (which hypothesis the data supports; read arms within-session, against the 2026-05-12 full-A 0/8) → kill-criterion read → non-claims → cost ($0) → reproducibility (the bash loop above) → next steps → see also.

Read the result against the spec's H5 decision table. Every outcome — including "neither variant recovers" — is publishable.

- [ ] **Step 4: Commit the writeup**

```bash
git add docs/research/2026-05-19-qwen-fix-a-isolation.md
git commit --signoff -m "docs(research): qwen-max fix-A isolation experiment result

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Push the branch and open a PR**

```bash
git push -u origin qwen-fix-a-isolation
```

Then open a PR with `gh pr create --base main` summarizing which fix-A feature the data implicated (or that neither variant recovered tool use), and linking PR #62 and the spec.

---

## Self-Review

**1. Spec coverage:**
- Refactor `VARIANT_SYSTEM` → `buildVariantSystem` — Task 1 Step 3. ✓
- Three variants (`control`/`variant-a`/`variant-b`) — Task 1 Step 3, `DIRECTIVES`. ✓
- `MYTHOS_VARIANT_PROMPT` read once in `variant-analyzer.ts`, unset → control, bad value → throw — Task 1 (`resolvePromptVariant`) + Task 2 Step 2. ✓
- Log active variant to stderr — Task 2 Step 2. ✓
- Unit tests for resolution + directive presence/absence — Task 1 Step 1. ✓
- Run qwen-max n=4 × 3 arms — Task 3 Step 1. ✓
- Publish `docs/research/2026-05-19-qwen-fix-a-isolation.md` — Task 3 Step 3. ✓
- Out of scope (fix C, full-A arm, CLI flag, 2×2) — honored: branch is off `main`, no `run.ts` changes, three arms only. ✓

**2. Placeholder scan:** No TBD/TODO. All code blocks are complete. Task 3's writeup content is described by section (mirroring an existing doc) rather than pre-written — acceptable because the content depends on run data that does not exist yet; the structure is fully specified.

**3. Type consistency:** `PromptVariant`, `buildVariantSystem`, `resolvePromptVariant` are named identically in Task 1 (definition), the Task 1 test, and Task 2 (import + use). `ACTIVE_PROMPT_VARIANT` / `VARIANT_SYSTEM` const names consistent within Task 2. The `DIRECTIVES` record is keyed by `PromptVariant`. ✓
