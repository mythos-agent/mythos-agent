# Design — qwen-max prompt-engineering experiment (Bundle A + C)

**Date:** 2026-05-12
**Issue trail:** [PR #61](https://github.com/mythos-agent/mythos-agent/pull/61) next-steps item 2, [issue #48](https://github.com/mythos-agent/mythos-agent/issues/48) Track A.
**Status:** approved, pre-implementation.

## TL;DR

Edit `VARIANT_SYSTEM` in `src/analysis/variant-analyzer.ts` to require a search-tool call before the model is allowed to emit a final variants answer (fix A — addresses the 1-turn give-up failure mode), and extend the `find_ast_pattern` `kind` description in `src/agent/tools.ts` with worked-example shapes that cover non-regex root causes (fix C — addresses the wrong-`kind=regex` failure mode on follow-redirects). Re-run the qwen-max n=4 calibration with `--results-subdir 2026-05-12-qwen-max-round{1..4}` and write up the result either way at `docs/research/2026-05-12-qwen-prompt-engineering.md`.

Goal: lift qwen-max's hit rate from 2/8 (25%) toward ≥4/8 (50%) on the same 2-case calibration corpus, with attribution-preserving turn logs.

## Hypothesis

**H4 (prompt-engineering claim):** Two targeted prompt edits — a "must call a search tool before answering" directive in the system prompt, and worked-example AST kinds in the `find_ast_pattern` schema — lift qwen-max's hit rate on the 2-case calibration corpus from 25% to ≥50%, without regressing the rounds where it already succeeded.

The 2026-05-11 qwen-max n=4 baseline is the comparison: rounds 1+2 hit on semver, rounds 3+4 missed on semver, all four missed on follow-redirects.

## Failure-mode arithmetic the design is built against

Re-derived from `benchmarks/variants-calibration/results/2026-05-11-qwen-max-round{1..4}/*.turns.jsonl`:

| Failure mode | Cases (8 total) | Diagnostic from turn log |
| --- | --- | --- |
| **A — 1-turn give-up** | round 3 semver, round 4 follow-redirects (2/8) | `stopReason: end_turn` on turn 1, `toolCalls: []`, `textPreview` contains correct `rootCauseAnalysis` and `"variants": []` |
| **B — over-escaped predicate** | round 4 semver (1/8) | `text_predicates: ["\\\\s\\*\|\\\\s\\+", "\\${.*?}"]` — second predicate's `{.*?}` is a malformed quantifier, treated as literal, filters every template_string match |
| **C — wrong AST `kind`** | rounds 1+2+3 follow-redirects (3/8) | `kind: "regex"` with predicates `["^(?:authorization\|cookie)$", "(?i)^(?!.*proxy-authorization).*"]` — the follow-redirects fix is in an array literal of header strings, not a regex AST node, so 0 matches |
| Successful | rounds 1+2 semver (2/8) | `kind: "template_string"` with single-escape predicate `["\\\\s\\*\|\\\\s\\+", "\\$\\{"]`, 9 variants with 5 in target band |

This design addresses A and C. B is held for a future round with cleaner attribution — see "Why B is excluded" below.

## Scope

### In scope

1. Edit `src/analysis/variant-analyzer.ts` `VARIANT_SYSTEM` to add a "Workflow — REQUIRED" section before "Output Format" that prohibits empty `variants` arrays unless at least one search tool has been called.
2. Edit `src/agent/tools.ts` `find_ast_pattern` `kind` schema `description` to list worked-example shapes that cover non-regex root causes.
3. Run n=4 qwen-max calibration against the same 2-case corpus with `--results-subdir 2026-05-12-qwen-max-round{1..4}`.
4. Compare round-by-round against `2026-05-11-qwen-max-round{1..4}` and aggregate hit rate.
5. Publish `docs/research/2026-05-12-qwen-prompt-engineering.md` whichever direction the data shows.

### Out of scope

- Tool-choice / `tool_choice: "any"` SDK-level forcing. Stays as a prose directive — keeps the change provider-agnostic and avoids depending on OpenAI-compat-adapter behavior for `tool_choice` pass-through.
- `qwen-plus` re-runs. The 0/8 result there is a different problem (model tier, not prompt). One axis at a time.
- Sonnet 4.6 re-runs with these edits. Worth doing eventually (PR #61 next-steps item 1), but not bundled here so we don't conflate "prompt edit helps qwen-max" with "prompt edit affects Sonnet's already-working loop."
- B (predicate over-escaping). Worked examples for predicate escaping would steer the model toward semver-shaped patterns and risk degrading the follow-redirects search. Hold for a follow-up.
- Tests. Prompt edits are not code-path changes; the existing `variant-analyzer.test.ts` and `tools.test.ts` continue to pass unchanged (no behavior changes to parsing or tool execution).

### Why B is excluded from this bundle

B has the smallest blast radius (1/8 misses) and the highest interference risk. A worked example showing how to write a correctly-escaped `text_predicates` regex would need to use one of the actual calibration shapes (whitespace-class regexes or header-allowlist arrays) as the example, which biases the model toward those shapes. That could degrade the wrong case while fixing the right one. Better experimental hygiene: ship A+C, read the data, then decide if B is worth a separate round.

## Concrete edits

### Edit 1 — `src/analysis/variant-analyzer.ts` `VARIANT_SYSTEM`

Add a "Workflow — REQUIRED" section after "Key Insight" and before "Output Format":

```
## Workflow — REQUIRED

1. Identify the root cause from the CVE (one sentence in `rootCauseAnalysis`).
2. Call `find_ast_pattern` (or `search_code` if the AST kind is unclear) AT LEAST ONCE to find candidate sites in the codebase.
3. Only after a tool call has returned, emit your final JSON answer.

An empty `variants` array is a valid answer — but only AFTER step 2. Emitting `variants: []` without calling any search tool is treated as a failed run, not a "no variants found" result. Identifying the root cause is step 1; mechanically searching for instances of it is step 2. Do NOT skip step 2.
```

Wording rationale: the directive is mechanical ("at least one tool call before final answer"), not motivational ("be thorough"). qwen-max's existing successful runs use exactly one `find_ast_pattern` call before answering — the directive matches the proven success pattern, not a more ambitious "≥3 tool calls" target that might cause new failure modes.

### Edit 2 — `src/agent/tools.ts` `find_ast_pattern` `kind` description

Replace the current `kind` `description` string with one that lists worked-example shapes:

```
'tree-sitter node kind to match. Pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class. Examples:
- ReDoS in template-literal regex builders → kind: "template_string"
- Header allowlist/denylist as inline strings → kind: "array" or "string" (NOT "regex" — the headers are array elements, not a regex literal)
- Comparison flaw → kind: "binary_expression"
- new RegExp(userInput) → kind: "new_expression"
- Function declaration with a specific parameter name → kind: "function_declaration"
May be a single string or an array of strings for union matching.'
```

Wording rationale: the lead sentence ("pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class") is the actual conceptual error that produced rounds 1-3 follow-redirects misses. The model picked `regex` because the *bug* is regex-shaped (a header allowlist regex), but the *fix* edits an array literal. The example list gives the model a quick lookup table for that translation.

## Experimental protocol

**Harness unchanged from 2026-05-11:**
- `npm run benchmark:variants-calibration -- --provider openai --model qwen-max --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 --results-subdir "2026-05-12-qwen-max-round$i" --log-turns`
- 4 rounds (i in 1..4), one `--results-subdir` per round
- Same 2 cases (GHSA-c2qf-rxjj-qqgw + GHSA-cxjh-pqwp-8mfp)
- Same fixture commits, MAX_TURNS=20, same parser
- `DASHSCOPE_API_KEY` set by the user in their Git Bash window — not passed via this design or prompt

**Variable changed:** only the prompt and the tool schema, via Edits 1 and 2 above.

**Attribution via turn logs:**
- A's effect → on yesterday's give-up turns (round 3 semver, round 4 follow-redirects), today's logs should show `toolCalls` non-empty on turn 1
- C's effect → on yesterday's wrong-kind follow-redirects turns, today's logs should show `kind` as something other than `"regex"` (ideally `"array"` or `"string"`)
- Either edit could fail independently and the JSONL diff tells us which

## Success / regression / kill bands

- **Success:** ≥4/8 combined hits across the n=4 qwen-max rounds. Publishable as "prompt engineering lifts qwen-max past 50% on the calibration corpus."
- **Mixed result:** 2-3/8 — same order as yesterday. Publishable as "edits failed to lift, here's the new failure-mode shape." This is still a useful writeup because the negative result distinguishes "qwen-max's loop is brittle in a way prompt edits can't fix" from "we picked the wrong edits."
- **Regression:** 0-1/8 — fewer hits than yesterday. Publishable as "edits actively harmed; the directive may be steering the model into a different failure mode." Negative result; informs whether more aggressive prompt work is worth doing on qwen-max at all.
- **Kill criterion (path-forward.md):** unchanged. Today's experiment does not gate the 2026-10-26 kill date — it's a follow-up on already-clearing-bar data.

## Cost

$0 — DashScope free tier, qwen-max, n=4. ~1 hr wall time based on yesterday's run.

## Risks and how the design handles them

- **Risk: the directive degrades the rounds that already worked.** Mitigation: the directive describes exactly the pattern qwen-max's successful rounds 1+2 already followed (1 tool call → emit JSON). It's not asking for new behavior on those rounds.
- **Risk: worked-example list biases the model toward semver-shape on follow-redirects, or vice versa.** Mitigation: the examples list covers 5 distinct shapes (`template_string`, `array`, `string`, `binary_expression`, `new_expression`, `function_declaration`) — no single shape is overrepresented. The lead sentence about "literal text being changed in the fix" is generic enough to apply to root causes outside the example list.
- **Risk: prompt edits help qwen-max but regress Sonnet.** Out of scope today, but worth noting in the writeup's "next steps" — Sonnet n=4 with this prompt is the cheapest answer.
- **Risk: 1-hour Qwen wall time blocks user.** No — the user runs the harness in their Git Bash window with their own `DASHSCOPE_API_KEY`; the harness's `--log-turns` output is what we analyze.

## Reproducibility (for the writeup)

The eventual `docs/research/2026-05-12-qwen-prompt-engineering.md` will document the new commit SHA and the same bash loop as `docs/research/2026-05-11-variants-v2-model-portability.md`, with `--results-subdir "2026-05-12-qwen-max-round$i"`.

## See also

- `docs/research/2026-05-11-variants-v2-model-portability.md` — yesterday's baseline this experiment targets.
- `docs/research/2026-04-27-variants-v2-first-match.md` — the Sonnet 4.6 origin run.
- `docs/path-forward.md` — Track A sub-PR sequence and kill criteria.
- [PR #61](https://github.com/mythos-agent/mythos-agent/pull/61) — yesterday's writeup PR; this experiment is item 2 of its "next steps."
