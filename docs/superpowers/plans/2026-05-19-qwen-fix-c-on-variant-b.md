# fix-C-on-variant-b Experiment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `find_ast_pattern` tool's `kind` schema description selectable at runtime via the `MYTHOS_FIND_AST_KIND_DOC` environment variable (`baseline` | `worked-examples`), so a qwen-max calibration run can measure whether fix C's worked-example AST-kind list moves the model off `kind: "regex"` on the follow-redirects case.

**Architecture:** All changes live in `src/agent/tools.ts` (357 lines, currently no `process.env` reads). A `FindAstKindDoc` type, two description-string constants, and a `resolveFindAstKindDoc` resolver are added after the imports. The active description is resolved once at module load from `MYTHOS_FIND_AST_KIND_DOC` (unset → `baseline`, the current behavior) and substituted into the `find_ast_pattern` schema. This mirrors the `MYTHOS_VARIANT_PROMPT` mechanism already on this branch's parent (`variant-analyzer.ts`): env var, fail-loud resolver, stderr provenance line, default = unchanged.

**Tech Stack:** TypeScript (ESM, `.js` import extensions), vitest.

**Research note (verified pre-plan):** the AST matcher (`src/analysis/ast-matcher/matcher.ts:113-127`) matches `kind` by a direct `Set.has(node.type)` check against tree-sitter node types — no allow-list. `"array"` and `"string"` are valid upstream `tree-sitter-javascript` node types, so fix C instructing the model to pick `kind: "array"` for an array-literal header allowlist will mechanically match. Unknown kinds return empty, no error. The experiment's premise is sound.

---

### Task 1: Add `MYTHOS_FIND_AST_KIND_DOC` selection to `tools.ts`

**Files:**
- Modify: `src/agent/tools.ts` (add a block after the imports at line 5; change the `kind` schema `description` at lines 84-86)
- Test: `src/agent/__tests__/tools.test.ts` (new file — no `tools.test.ts` exists today)

- [ ] **Step 1: Write the failing test**

Create `src/agent/__tests__/tools.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import {
  createAgentTools,
  resolveFindAstKindDoc,
  KIND_DOC_BASELINE,
  KIND_DOC_WORKED_EXAMPLES,
} from "../tools.js";

// The fix-C isolation experiment (docs/research/2026-05-19-qwen-fix-c-on-variant-b.md)
// makes the find_ast_pattern `kind` schema description selectable via
// MYTHOS_FIND_AST_KIND_DOC. These tests pin the resolver behavior and
// the two description variants. Tests run with the env var unset, so
// the module-load default resolves to "baseline".

describe("resolveFindAstKindDoc", () => {
  it("treats unset and empty string as baseline", () => {
    expect(resolveFindAstKindDoc(undefined)).toBe("baseline");
    expect(resolveFindAstKindDoc("")).toBe("baseline");
  });

  it("passes through recognized values", () => {
    expect(resolveFindAstKindDoc("baseline")).toBe("baseline");
    expect(resolveFindAstKindDoc("worked-examples")).toBe("worked-examples");
  });

  it("throws on an unrecognized value, naming the bad value", () => {
    expect(() => resolveFindAstKindDoc("worked_examples")).toThrow(
      /worked_examples/
    );
  });
});

describe("find_ast_pattern kind descriptions", () => {
  it("baseline is the terse description, no worked examples", () => {
    expect(KIND_DOC_BASELINE).toContain("tree-sitter node kind to match");
    expect(KIND_DOC_BASELINE).not.toContain("Pick the kind that holds");
  });

  it("worked-examples lists the header-allowlist shape that targets mode C", () => {
    expect(KIND_DOC_WORKED_EXAMPLES).toContain(
      "Pick the kind that holds the LITERAL TEXT"
    );
    expect(KIND_DOC_WORKED_EXAMPLES).toContain(
      "Header allowlist/denylist as inline strings"
    );
    expect(KIND_DOC_WORKED_EXAMPLES).toContain('(NOT "regex"');
  });
});

describe("createAgentTools wiring", () => {
  it("find_ast_pattern's kind description is the baseline doc when env is unset", () => {
    const tools = createAgentTools(".");
    const findAst = tools.find((t) => t.name === "find_ast_pattern");
    expect(findAst).toBeDefined();
    const schema = findAst!.input_schema as {
      properties: { kind: { description: string } };
    };
    expect(schema.properties.kind.description).toBe(KIND_DOC_BASELINE);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/agent/__tests__/tools.test.ts`
Expected: FAIL — `tools.ts` does not export `resolveFindAstKindDoc`, `KIND_DOC_BASELINE`, or `KIND_DOC_WORKED_EXAMPLES` yet.

- [ ] **Step 3: Add the type, constants, and resolver to `tools.ts`**

The current top of `src/agent/tools.ts` is:

```typescript
import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type Anthropic from "@anthropic-ai/sdk";
import { findAstPattern, inferLanguage } from "../analysis/ast-matcher/index.js";

export function createAgentTools(projectPath: string): Anthropic.Tool[] {
```

Insert the following block between the last import (line 5) and `export function createAgentTools` (line 7), so it sits immediately before `createAgentTools`:

```typescript
/**
 * `find_ast_pattern`'s `kind` schema description is selectable for the
 * fix-C isolation experiment — see
 * docs/research/2026-05-19-qwen-fix-c-on-variant-b.md. `baseline` is the
 * original terse description; `worked-examples` is the fix-C variant
 * from PR #62 that lists worked AST-kind shapes (keyed off "pick the
 * kind that holds the LITERAL TEXT being changed in the fix"). The
 * active description is resolved once at module load from
 * MYTHOS_FIND_AST_KIND_DOC (unset -> baseline, unchanged behavior) and
 * logged to stderr so each calibration run records which doc it used.
 */
export type FindAstKindDoc = "baseline" | "worked-examples";

export const KIND_DOC_BASELINE =
  'tree-sitter node kind to match (e.g. "call_expression", "new_expression", "function_declaration", "regex", "template_string"). May be a single string or an array of strings for union matching.';

export const KIND_DOC_WORKED_EXAMPLES =
  "tree-sitter node kind to match. Pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class. Examples:\n" +
  '- ReDoS in template-literal regex builders → kind: "template_string"\n' +
  '- Header allowlist/denylist as inline strings → kind: "array" or "string" (NOT "regex" — the headers are array elements, not a regex literal)\n' +
  '- Comparison flaw → kind: "binary_expression"\n' +
  '- new RegExp(userInput) → kind: "new_expression"\n' +
  '- Function declaration with a specific parameter name → kind: "function_declaration"\n' +
  "May be a single string or an array of strings for union matching.";

/**
 * Resolve the MYTHOS_FIND_AST_KIND_DOC env value to a FindAstKindDoc.
 * Unset or empty -> `baseline`. An unrecognized value throws, so a typo
 * fails loud instead of silently running the baseline arm.
 */
export function resolveFindAstKindDoc(
  raw: string | undefined
): FindAstKindDoc {
  if (raw === undefined || raw === "") return "baseline";
  if (raw === "baseline" || raw === "worked-examples") return raw;
  throw new Error(
    `Invalid MYTHOS_FIND_AST_KIND_DOC="${raw}". Valid values: baseline, worked-examples (or unset for baseline).`
  );
}

const ACTIVE_FIND_AST_KIND_DOC: FindAstKindDoc = resolveFindAstKindDoc(
  process.env.MYTHOS_FIND_AST_KIND_DOC
);
const KIND_DESCRIPTION =
  ACTIVE_FIND_AST_KIND_DOC === "worked-examples"
    ? KIND_DOC_WORKED_EXAMPLES
    : KIND_DOC_BASELINE;
process.stderr.write(
  `[tools] find_ast kind doc: ${ACTIVE_FIND_AST_KIND_DOC}\n`
);
```

- [ ] **Step 4: Point the schema at the resolved description**

In `src/agent/tools.ts`, the `find_ast_pattern` tool's `kind` property currently reads (around lines 82-87):

```typescript
          kind: {
            type: ["string", "array"],
            items: { type: "string" },
            description:
              'tree-sitter node kind to match (e.g. "call_expression", "new_expression", "function_declaration", "regex", "template_string"). May be a single string or an array of strings for union matching.',
          },
```

Replace the inline `description:` string with the module-level constant, so it reads:

```typescript
          kind: {
            type: ["string", "array"],
            items: { type: "string" },
            description: KIND_DESCRIPTION,
          },
```

Leave every other tool and property in `createAgentTools` untouched.

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run src/agent/__tests__/tools.test.ts`
Expected: PASS — all 6 tests green.

- [ ] **Step 6: Run the full suite and the type-checker**

Run: `npm test`
Expected: PASS — all tests green. The new `tools.test.ts` plus every existing suite. `tools.ts` is imported widely; a broken export or a module-load throw would fail many suites.

Run: `npm run typecheck`
Expected: exit 0, no errors.

- [ ] **Step 7: Verify the env var is read end-to-end**

Run: `npm run build`
Expected: exit 0.

Run: `MYTHOS_FIND_AST_KIND_DOC=worked-examples node -e "import('./dist/agent/tools.js').then(() => {})"`
Expected: stderr prints `[tools] find_ast kind doc: worked-examples`.

Run: `node -e "import('./dist/agent/tools.js').then(() => {})"`
Expected: stderr prints `[tools] find_ast kind doc: baseline`.

Run: `MYTHOS_FIND_AST_KIND_DOC=bogus node -e "import('./dist/agent/tools.js').then(() => {}).catch(e => { console.error(e.message); process.exit(1); })"`
Expected: stderr prints the `Invalid MYTHOS_FIND_AST_KIND_DOC="bogus"` error and exits non-zero.

> If `npm run build` is not defined or the `dist/` path differs, report what you found and adapt — the point of this step is one positive, one default, and one error case proving the env var reaches `resolveFindAstKindDoc`.

- [ ] **Step 8: Format the changed files**

Run: `npx prettier --write src/agent/tools.ts src/agent/__tests__/tools.test.ts`
Expected: both files reported as written (or already formatted).

> Do NOT run `npm run format` — it reformats all of `src/` and pollutes the working tree. Only the two files above.

- [ ] **Step 9: Commit**

```bash
git add src/agent/tools.ts src/agent/__tests__/tools.test.ts
git commit --signoff -m "feat(tools): select find_ast_pattern kind doc via MYTHOS_FIND_AST_KIND_DOC

The find_ast_pattern `kind` schema description is now selectable at
module load: `baseline` (the original terse description) or
`worked-examples` (the fix-C variant from PR #62 listing worked
AST-kind shapes). Unset -> baseline (unchanged behavior). Enables the
fix-C-on-variant-b calibration run. Resolver throws on a bad value;
active doc logged to stderr for per-run provenance.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Run the calibration and write up the result

**Files:**
- Create: `docs/research/2026-05-19-qwen-fix-c-on-variant-b.md`

**Context:** Gated on the user running the harness — it needs `DASHSCOPE_API_KEY`, which only the user has, in their Git Bash window. The implementer must NOT attempt to run the harness or ask for the key.

- [ ] **Step 1: Hand the harness command to the user**

Post this block for the user to run in their Git Bash window (with `DASHSCOPE_API_KEY` already exported):

```bash
for c in baseline worked-examples; do
  for i in 1 2 3 4; do
    MYTHOS_VARIANT_PROMPT=variant-b MYTHOS_FIND_AST_KIND_DOC=$c \
    npm run benchmark:variants-calibration -- \
      --provider openai --model qwen-max \
      --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
      --results-subdir "2026-05-19-fixc-$c-round$i" \
      --log-turns
  done
done
```

Then STOP and wait. Do not proceed to Step 2 until the user confirms the 8 result directories exist under `benchmarks/variants-calibration/results/2026-05-19-fixc-{baseline,worked-examples}-round{1..4}/`.

- [ ] **Step 2: Analyze the results**

For each of the 16 `*.turns.jsonl` files, record turn-1 `stopReason`, whether `toolCalls` is non-empty, and the turn-1 `find_ast_pattern` `kind` value. For each of the 8 `summary.json` files, record `matched` per case. Build a per-arm table with these columns: turn-1 tool-call rate, the follow-redirects `kind` choice (`regex` vs `array`/`string`/other), the semver `kind` choice (should stay `template_string`), and hit rate.

The primary signal is the follow-redirects `kind` choice: does `worked-examples` move it off `regex` relative to the same-session `baseline` arm? Watch the guards: did mode A (turn-1 give-ups) return under the longer `worked-examples` schema, and did semver's `kind` choice regress off `template_string`.

- [ ] **Step 3: Write `docs/research/2026-05-19-qwen-fix-c-on-variant-b.md`**

Mirror the structure of `docs/research/2026-05-19-qwen-fix-a-isolation.md`: TL;DR → why this writeup exists → hypothesis (H6, with the decision table from the spec `docs/superpowers/specs/2026-05-19-qwen-fix-c-on-variant-b-design.md`) → methodology (note both env vars, `MYTHOS_VARIANT_PROMPT=variant-b` held constant, and the commit SHA) → runs (per-arm table) → attribution (read arms within-session — does fix C move the follow-redirects `kind`) → kill-criterion read → non-claims → cost ($0) → reproducibility (the bash loop above) → next steps → see also.

Read the result against the spec's H6 decision table. Every outcome is publishable, including a null result. Note the `kind: "string"` over-breadth caveat from the spec if the model picks `kind: "string"`.

- [ ] **Step 4: Commit the writeup**

```bash
git add docs/research/2026-05-19-qwen-fix-c-on-variant-b.md
git commit --signoff -m "docs(research): fix-C-on-variant-b experiment result

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Push the branch and open a PR**

```bash
git push -u origin qwen-fix-c-on-variant-b
```

Then open a PR. Base it on `qwen-fix-a-isolation` if PR #63 has not merged yet (stacked PR), or on `main` if PR #63 has merged. Summarize whether fix C moved the follow-redirects `kind` off `regex`, and link PR #63 and the spec.

---

## Self-Review

**1. Spec coverage:**
- `MYTHOS_FIND_AST_KIND_DOC` env support, `resolveFindAstKindDoc`, two `kind`-doc strings — Task 1 Steps 3. ✓
- Unset → `baseline`, unrecognized → throw — Task 1 Step 3 (`resolveFindAstKindDoc`). ✓
- Wire resolved description into the `find_ast_pattern` schema — Task 1 Step 4. ✓
- Unit-test resolver + description selection — Task 1 Step 1. ✓
- stderr provenance line — Task 1 Step 3 (`[tools] find_ast kind doc: …`). ✓
- Run qwen-max n=4 × 2 arms, `MYTHOS_VARIANT_PROMPT=variant-b` held constant — Task 2 Step 1. ✓
- Publish `docs/research/2026-05-19-qwen-fix-c-on-variant-b.md` — Task 2 Step 3. ✓
- Fix C verbatim from PR #62 `313661c` — `KIND_DOC_WORKED_EXAMPLES` in Task 1 Step 3 is the verbatim string. ✓
- Out of scope (mode B, the prompt dimension, refined fix C, other models) — honored: only `tools.ts` changes, prompt held at `variant-b` by the harness invocation, fix C copied verbatim. ✓

**2. Placeholder scan:** No TBD/TODO. All code blocks complete. Task 2's writeup content is specified by section (mirroring an existing doc) because it depends on run data that does not exist yet — the structure is fully pinned.

**3. Type consistency:** `FindAstKindDoc`, `resolveFindAstKindDoc`, `KIND_DOC_BASELINE`, `KIND_DOC_WORKED_EXAMPLES` are named identically in Task 1's definition (Step 3), the Task 1 test (Step 1), and the schema wiring (Step 4 uses `KIND_DESCRIPTION`, defined in Step 3). `ACTIVE_FIND_AST_KIND_DOC` and `KIND_DESCRIPTION` are consistent within Step 3. ✓
