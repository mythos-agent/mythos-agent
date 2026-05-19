# qwen-max prompt-engineering experiment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift qwen-max's hit rate on the 2-case variants v2 calibration corpus from yesterday's 2/8 (25%) toward ≥4/8 (50%) by editing `VARIANT_SYSTEM` (force tool use before final answer — fix A) and the `find_ast_pattern` `kind` schema description (worked-example AST kinds — fix C), then publish whichever direction the n=4 data shows at `docs/research/2026-05-12-qwen-prompt-engineering.md`.

**Architecture:** Two prompt edits, no code-path changes. Edit 1 inserts a "Workflow — REQUIRED" section into `VARIANT_SYSTEM` so the model must call a search tool before emitting variants. Edit 2 rewrites the `kind` field description with worked-example shapes mapping bug archetypes → AST node kinds. Existing unit tests do not snapshot prompt text and remain unaffected. The user runs the harness with their `DASHSCOPE_API_KEY` against `--model qwen-max` n=4; per-turn JSONL logs preserve attribution between the two edits.

**Tech Stack:** TypeScript, vitest, the existing variants-calibration harness (`benchmarks/variants-calibration/run.ts`), DashScope free-tier OpenAI-compat endpoint.

**Spec:** `docs/superpowers/specs/2026-05-12-qwen-prompt-engineering-design.md` (commit `f616159`).

---

## File map

| File | Action | Purpose |
| --- | --- | --- |
| `src/analysis/variant-analyzer.ts` | Modify (lines 26-64 — the `VARIANT_SYSTEM` template literal) | Insert "Workflow — REQUIRED" between "Key Insight" and "Output Format" |
| `src/agent/tools.ts` | Modify (lines 82-87 — the `kind` field description on the `find_ast_pattern` tool) | Replace one-line description with worked-example list |
| `docs/research/2026-05-12-qwen-prompt-engineering.md` | Create | Publish n=4 result (improvement, mixed, or regression) |

No new files, no test changes, no harness changes.

---

## Task 1: Edit VARIANT_SYSTEM to require tool use before final answer (fix A)

**Files:**
- Modify: `src/analysis/variant-analyzer.ts:26-64`

The current `VARIANT_SYSTEM` template literal has three sections: "How Variant Analysis Works", "Key Insight", "Output Format". Insert a new "Workflow — REQUIRED" section between "Key Insight" and "Output Format". Existing text in the other sections is unchanged.

- [ ] **Step 1: Apply the edit**

In `src/analysis/variant-analyzer.ts`, find the text:

```
## Key Insight
Don't match surface syntax. Match the UNDERLYING MISTAKE. A buffer overflow in a URL parser and a buffer overflow in a JSON parser have the same root cause pattern even though the code looks completely different.

## Output Format
```

and replace it with:

```
## Key Insight
Don't match surface syntax. Match the UNDERLYING MISTAKE. A buffer overflow in a URL parser and a buffer overflow in a JSON parser have the same root cause pattern even though the code looks completely different.

## Workflow — REQUIRED

1. Identify the root cause from the CVE (one sentence in \`rootCauseAnalysis\`).
2. Call \`find_ast_pattern\` (or \`search_code\` if the AST kind is unclear) AT LEAST ONCE to find candidate sites in the codebase.
3. Only after a tool call has returned, emit your final JSON answer.

An empty \`variants\` array is a valid answer — but only AFTER step 2. Emitting \`variants: []\` without calling any search tool is treated as a failed run, not a "no variants found" result. Identifying the root cause is step 1; mechanically searching for instances of it is step 2. Do NOT skip step 2.

## Output Format
```

Use the Edit tool. Note that the source already uses escaped backticks (`` \` ``) inside the template literal — keep that escaping for the inline `find_ast_pattern`, `search_code`, `rootCauseAnalysis`, and `variants` references in the new section.

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: clean exit (no TypeScript errors). The change is purely a string literal modification; no types touched.

- [ ] **Step 3: Run the existing analyzer test suite to confirm no snapshot breakage**

Run: `npx vitest run src/analysis/__tests__/variant-analyzer.test.ts src/analysis/calibration`
Expected: all tests pass. The variant-analyzer tests target `parseVariants` and the agent-runner, not the prompt content; they remain green.

---

## Task 2: Edit find_ast_pattern kind description with worked-example AST kinds (fix C)

**Files:**
- Modify: `src/agent/tools.ts:82-87`

The `find_ast_pattern` tool's `kind` field currently has a flat one-line description. Replace it with a worked-example list that maps bug archetypes to AST node kinds, leading with the conceptual instruction "pick the kind that holds the literal text being changed in the fix."

- [ ] **Step 1: Apply the edit**

In `src/agent/tools.ts`, find:

```ts
          kind: {
            type: ["string", "array"],
            items: { type: "string" },
            description:
              'tree-sitter node kind to match (e.g. "call_expression", "new_expression", "function_declaration", "regex", "template_string"). May be a single string or an array of strings for union matching.',
          },
```

and replace the `description` value with the multi-line worked-example list:

```ts
          kind: {
            type: ["string", "array"],
            items: { type: "string" },
            description:
              'tree-sitter node kind to match. Pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class. Examples:\n' +
              '- ReDoS in template-literal regex builders → kind: "template_string"\n' +
              '- Header allowlist/denylist as inline strings → kind: "array" or "string" (NOT "regex" — the headers are array elements, not a regex literal)\n' +
              '- Comparison flaw → kind: "binary_expression"\n' +
              '- new RegExp(userInput) → kind: "new_expression"\n' +
              '- Function declaration with a specific parameter name → kind: "function_declaration"\n' +
              'May be a single string or an array of strings for union matching.',
          },
```

Use string concatenation with explicit `\n` (rather than a multi-line template literal) so the description renders cleanly in any tooling that displays the schema and doesn't accidentally include leading whitespace from source indentation.

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: clean exit.

- [ ] **Step 3: Lint**

Run: `npm run lint`
Expected: clean exit. No new rules touched — the change is content inside an existing string literal.

- [ ] **Step 4: Run the agent test suite**

Run: `npx vitest run src/agent src/analysis/ast-matcher`
Expected: all tests pass. The agent tests (`analyzer.test.ts`, `analyzer-loop.test.ts`, `prompts.test.ts`) target the analyzer loop logic, not the schema description text.

---

## Task 3: Full test pass and commit the two prompt edits

**Files:**
- No new file changes — this task verifies and commits Tasks 1 and 2 together.

- [ ] **Step 1: Full test pass**

Run: `npm test`
Expected: all tests pass.

- [ ] **Step 2: Format check**

Run: `npm run format:check`
Expected: clean exit. If it fails on the two edited files, run `npm run format` to auto-fix and re-run `format:check` until clean.

- [ ] **Step 3: Commit**

```bash
git add src/analysis/variant-analyzer.ts src/agent/tools.ts
git commit --signoff -m "$(cat <<'EOF'
fix(variants): force tool use + AST-kind worked examples (qwen-max prompt-eng)

VARIANT_SYSTEM now requires at least one find_ast_pattern/search_code
call before emitting a final answer — addresses the 1-turn give-up
failure mode in 2026-05-11 qwen-max rounds 3 (semver) and 4
(follow-redirects). find_ast_pattern's `kind` description gains a
worked-example list keyed off "pick the kind that holds the literal
text being changed in the fix, not the kind that describes the bug
class" — addresses the wrong-kind=regex failure mode that produced
0/4 on follow-redirects.

Pre-registered bundle A+C from PR #61's next-steps list (B held for
a follow-up to keep attribution narrow). Spec at
docs/superpowers/specs/2026-05-12-qwen-prompt-engineering-design.md.
The 2026-05-12 n=4 calibration run follows.
EOF
)"
```

Note: the trailing `Co-Authored-By` is added by the repo's commit-msg hook on `--signoff`-style commits; if the hook does not append it, append it manually before committing. The repo's CI gate requires a DCO `Signed-off-by` trailer — `--signoff` covers that.

- [ ] **Step 4: Confirm clean working tree**

Run: `git status`
Expected: clean working tree, branch `main` ahead by one commit (the prompt-edits commit) on top of `f616159` (the spec commit).

---

## Task 4: Run the n=4 qwen-max calibration

**Files:**
- Generates: `benchmarks/variants-calibration/results/2026-05-12-qwen-max-round{1..4}/` (4 directories, each with `summary.json`, `GHSA-c2qf-rxjj-qqgw.json`, `GHSA-c2qf-rxjj-qqgw.turns.jsonl`, `GHSA-cxjh-pqwp-8mfp.json`, `GHSA-cxjh-pqwp-8mfp.turns.jsonl`)

This task runs in the user's Git Bash window with `DASHSCOPE_API_KEY` already exported. The implementation agent should NOT run the harness (the agent has no DashScope key and the user explicitly asked not to be prompted for one). The agent's role is to provide the exact command and wait for the user to confirm the results subdirs appear.

- [ ] **Step 1: Confirm the user has DASHSCOPE_API_KEY set**

Ask the user: "Is `DASHSCOPE_API_KEY` exported in your Git Bash window?" Do not proceed until confirmed yes.

- [ ] **Step 2: Provide the exact bash loop to the user**

The user should paste this into their Git Bash window:

```bash
for i in 1 2 3 4; do
  npm run benchmark:variants-calibration -- \
    --provider openai --model qwen-max \
    --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
    --results-subdir "2026-05-12-qwen-max-round$i" \
    --log-turns
done
```

This mirrors the 2026-05-11 reproducibility block (lines 158-164 of `docs/research/2026-05-11-variants-v2-model-portability.md`) with only the `--results-subdir` date prefix changed.

- [ ] **Step 3: Wait for completion**

The 2026-05-11 run took ~1 hour wall time for the qwen-max half. Expect similar today.

- [ ] **Step 4: Confirm the four result directories exist**

Run: `ls benchmarks/variants-calibration/results/ | grep 2026-05-12-qwen-max`
Expected: 4 lines, one per round.

---

## Task 5: Analyze the round-by-round results

**Files:**
- Read-only: `benchmarks/variants-calibration/results/2026-05-12-qwen-max-round{1..4}/summary.json` and `*.turns.jsonl`
- Compare against: `benchmarks/variants-calibration/results/2026-05-11-qwen-max-round{1..4}/`

The analysis feeds the writeup. Produce a per-round disposition table and an aggregate hit rate, plus a fix-attribution read keyed off the turn logs.

- [ ] **Step 1: Build the per-round hits table**

For each of the 4 rounds, read `summary.json` and record `matched` for both GHSA cases. The aggregate is the count of `matched: true` across the 8 case-runs.

- [ ] **Step 2: Compare against yesterday's hits table**

Yesterday's disposition (from `docs/research/2026-05-11-variants-v2-model-portability.md`):

| Round | Semver | Follow-redirects |
| --- | --- | --- |
| 1 | MATCH | miss (wrong kind=regex) |
| 2 | MATCH | miss (wrong kind=regex) |
| 3 | miss (1-turn give-up) | miss (wrong kind=regex) |
| 4 | miss (over-escaped predicate) | miss (1-turn give-up) |

Today's bands per the spec:
- **Success:** combined ≥4/8 hits
- **Mixed:** 2-3/8 (same order as yesterday)
- **Regression:** 0-1/8

- [ ] **Step 3: Read turn logs to attribute lift (or regression) to fix A vs fix C**

For each of today's 8 case-runs, read the round's `*.turns.jsonl` and record:

- **Did the model call a tool on turn 1?** (A's signal — yesterday, 2 of 8 turn-1s had `toolCalls: []`; today they should not, if A is doing its job)
- **For follow-redirects rounds, what `kind` did the model pick?** (C's signal — yesterday all 3 attempted calls used `kind: "regex"`; today they should use `array` or `string` if C is doing its job)
- **Did over-escaped predicates persist?** (B's signal — not fixed by today's bundle, but useful to note whether B remains a 1/8 issue or has changed shape)

This three-axis read is the substance of the writeup's "Combined model picture" section.

- [ ] **Step 4: Stash the analysis in working memory for the writeup**

No file write yet — just internalize the round-by-round attribution before drafting the writeup. Continue to Task 6.

---

## Task 6: Draft docs/research/2026-05-12-qwen-prompt-engineering.md

**Files:**
- Create: `docs/research/2026-05-12-qwen-prompt-engineering.md`

Mirror the structure of `docs/research/2026-05-11-variants-v2-model-portability.md` (the immediately-prior writeup in this arc).

- [ ] **Step 1: Write the TL;DR**

One paragraph. State the hit-rate delta (today's combined hits vs yesterday's 2/8), the band the data falls in (success/mixed/regression), and the cost ($0).

- [ ] **Step 2: Write "Why this writeup exists"**

Reference PR #61's next-steps list item 2 and the failure-mode taxonomy from yesterday. One short paragraph.

- [ ] **Step 3: Write the Hypothesis section**

State H4 verbatim from the spec ("two targeted prompt edits lift qwen-max from 25% to ≥50% on the 2-case calibration corpus, without regressing the rounds that already succeeded"). Include the spec link.

- [ ] **Step 4: Write the Methodology section**

Two subsections:
- **Unchanged from 2026-05-11:** harness, calibration cases, fixture commits, agent loop file, MAX_TURNS, parser, model (`qwen-max`), provider/base URL.
- **Changed:** the two prompt edits with the exact text from Tasks 1 and 2, and link to the commit SHA from Task 3.

- [ ] **Step 5: Write the Runs section**

A `qwen-max (n=4) — 2026-05-12 (post prompt edits)` table mirroring the 2026-05-11 layout: 4 rows × (semver, follow-redirects, combined) columns. For each cell, include disposition (MATCH / miss-shape), wall time, turn count, and the specific tool input the model emitted (especially `kind` for follow-redirects).

- [ ] **Step 6: Write the failure-mode taxonomy update**

If today's runs show new failure modes, document them. If they show A-mode (1-turn give-up) reduced and C-mode (wrong-kind on follow-redirects) reduced, document the residual misses. The honest framing is the one PR #61 used: "the pattern is" (whatever the data actually shows).

- [ ] **Step 7: Write the combined model picture**

A table comparing today's qwen-max vs yesterday's qwen-max vs the 2026-04-27 Sonnet 4.6 baseline. Same columns as PR #61's table: Rounds, Hits, Semver, Follow-redirects, Wall time, Tool-use depth.

- [ ] **Step 8: Write "What this proves about the kill criterion"**

Per the spec, the kill criterion in `docs/path-forward.md` is unchanged by today's experiment. State that explicitly. If today's hit rate is ≥4/8, note that the kill criterion is comfortably cleared on qwen-max (which yesterday's writeup also clears on rounds 1+2). If today's hit rate is 0-1/8, the kill criterion is still about Sonnet, not qwen-max, and remains unchanged.

- [ ] **Step 9: Write "What this writeup deliberately does not claim"**

Bullets, verbatim from the spec's "What this writeup will commit to NOT claiming" section:
- Qwen-max is production-ready for variant hunting (n=4 on 2 cases is not production data)
- Prompt engineering can lift any model (qwen-plus untested today)
- These edits are universal (targets qwen-max's specific 2026-05-11 failure taxonomy; Sonnet behavior with these edits is unknown)
- mythos-agent has found a 0-day (same disclaimer as PR #59 and PR #61)

- [ ] **Step 10: Write Cost section**

Mirror PR #61's format: model | rounds | provider | API cost. Single row: `qwen-max | 4 | DashScope (free tier) | $0`. Total today: $0. Cumulative arc cost: ~$23 (carried over from PR #61) + $0 today = ~$23 across four writeups.

- [ ] **Step 11: Write Reproducibility section**

The same bash block from Task 4, plus a `git checkout <SHA>` line for the prompt-edits commit. Note expected wall time (~1 hr for the qwen-max half).

- [ ] **Step 12: Write Next steps section**

In priority order, propose:
1. Whatever experiment naturally follows from today's outcome (e.g., if A worked but C didn't, the next experiment is "C-only with different worked examples"; if A+C cleared 50%, the next experiment is "Sonnet 4.6 n=4 with the new prompt to verify no regression")
2. Sonnet 4.6 n=4 reliability runs (carried over from PR #61 next-step item 1 if not addressed in #1 above)
3. B (over-escaped predicate fix) as the standalone next-round experiment
4. A4 — the real variant-hunt re-run

- [ ] **Step 13: Write "See also" section**

Links to: PR #61 spec; 2026-05-11 writeup; 2026-04-27 first-match writeup; `docs/path-forward.md`; the prompt-edits commit.

---

## Task 7: Commit and PR the writeup

**Files:**
- The created `docs/research/2026-05-12-qwen-prompt-engineering.md` from Task 6

- [ ] **Step 1: Commit the writeup**

```bash
git add docs/research/2026-05-12-qwen-prompt-engineering.md
git commit --signoff -m "$(cat <<'EOF'
docs(research): qwen-max prompt-engineering n=4 (2026-05-12)

Result write-up of the bundle A+C prompt edits shipped in <SHA>:
force-tool-use directive in VARIANT_SYSTEM and worked-example AST
kinds in find_ast_pattern's schema. Compares round-by-round against
the 2026-05-11 qwen-max baseline; same harness, same corpus, same
$0 DashScope free-tier budget.
EOF
)"
```

Replace `<SHA>` with the actual commit hash from Task 3.

- [ ] **Step 2: Push and open a PR**

```bash
git push -u origin HEAD
gh pr create --title "docs(research): qwen-max prompt-engineering n=4 (2026-05-12)" --body "$(cat <<'EOF'
## Summary
- Bundle A+C prompt edits land in a prior commit on this PR; this commit publishes the n=4 outcome.
- Force-tool-use directive in `VARIANT_SYSTEM` targets yesterday's 1-turn give-up misses (2/8 of yesterday's runs).
- Worked-example AST kinds in `find_ast_pattern` target yesterday's wrong-`kind=regex` follow-redirects misses (3/8).
- Per-turn JSONL logs preserve fix-A vs fix-C attribution across the 4 rounds.

## Test plan
- [ ] `npm test` passes locally on the prompt-edits commit
- [ ] All four `2026-05-12-qwen-max-round{1..4}` result directories present and well-formed
- [ ] Writeup's per-round disposition table matches `summary.json` for each round
- [ ] Writeup correctly identifies which failure modes were/weren't addressed via the turn logs

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Both the prompt-edits commit and the writeup commit ship on the same PR.

---

## Self-review against the spec

**Spec coverage check (every requirement maps to a task):**

| Spec requirement | Task |
| --- | --- |
| Edit `VARIANT_SYSTEM` to require a search tool before emitting variants | Task 1 |
| Edit `find_ast_pattern` `kind` description with worked-example shapes | Task 2 |
| Run n=4 qwen-max with `--results-subdir 2026-05-12-qwen-max-round{1..4}` | Task 4 |
| Compare against `2026-05-11-qwen-max-round{1..4}` round-by-round + aggregate | Task 5 |
| Publish `docs/research/2026-05-12-qwen-prompt-engineering.md` either direction | Task 6 |
| Out-of-scope items (qwen-plus, Sonnet, B, tool_choice SDK forcing) | Honored — no tasks for these |
| DCO sign-off | Both Task 3 and Task 7 commits use `--signoff` |
| Three publishable bands defined and writeup commits to them | Task 5 Step 2 and Task 6 Step 1 |
| Attribution via turn logs | Task 5 Step 3 |
| Risks acknowledged in writeup's non-claims | Task 6 Step 9 |

**Placeholder scan:** All steps show actual content (edit text, commands, expected outputs). No "TBD" / "fill in details" / "similar to Task N" wording.

**Type consistency:** No new types introduced. The two file edits modify existing string literal contents; no method signatures, no property renames.
