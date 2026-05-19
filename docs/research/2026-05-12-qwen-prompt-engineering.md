# Variants v2 — qwen-max Prompt-Engineering Experiment (Bundle A+C) — 2026-05-12

> **TL;DR.** A pre-registered two-edit prompt change — a "must call a search tool before answering" workflow directive in `VARIANT_SYSTEM` (fix A), plus worked-example AST `kind` shapes in the `find_ast_pattern` tool schema (fix C) — was run n=4 on `qwen-max` against the same 2-case calibration corpus as the [2026-05-11 baseline](2026-05-11-variants-v2-model-portability.md). Result: **0/8 hits**, down from yesterday's 2/8 (25%). This lands in the pre-registered **regression band (0–1/8)**. Every one of the 8 case-runs failed via the *exact* failure mode fix A was written to eliminate — the 1-turn give-up: `stopReason: end_turn` on turn 1, `toolCalls: []`, a correct `rootCauseAnalysis`, and `"variants": []`. The two semver rounds that *matched* yesterday now give up too. Fix C could not be evaluated at all: the model never called `find_ast_pattern` in any run, so the new `kind` description was never exercised. The most defensible reading is that fix A's directive — which quotes the give-up output `variants: []` verbatim while telling the model not to produce it — acted as a negative-example prime that *universalized* the give-up rather than suppressing it. Total cost: **\$0** (DashScope free tier). The edits are not merged to `main`; this writeup is the negative result, and the branch will not ship the prompt change as-is.

## Why this writeup exists

The [2026-05-11 model-portability probe](2026-05-11-variants-v2-model-portability.md) measured `qwen-max` at 2/8 and diagnosed three distinct failure modes from the turn logs:

- **A — 1-turn give-up** (2/8: round 3 semver, round 4 follow-redirects): `end_turn` on turn 1 with no tool calls and an empty `variants` array.
- **B — over-escaped predicate** (1/8: round 4 semver): a doubled-backslash `text_predicates` regex that matches literal backslashes and returns 0 results.
- **C — wrong AST `kind`** (3/8: rounds 1–3 follow-redirects): `kind: "regex"` on a fix that lives in an array literal of header strings, returning 0 results.

[PR #61](https://github.com/mythos-agent/mythos-agent/pull/61)'s next-steps list, item 2, proposed prompt engineering as the cheapest lever to lift `qwen-max` past 50%. This experiment is that item. It pre-registered **Bundle A+C** — fix A targets the 2/8 give-ups, fix C targets the 3/8 wrong-`kind` misses — and deliberately *excluded* fix B to keep attribution narrow (design rationale in `docs/superpowers/specs/2026-05-12-qwen-prompt-engineering-design.md`). The design's success/regression/kill bands were written *before* the run, so today's data reads against a fixed yardstick rather than a post-hoc one.

The 2026-04-26 negative-result writeup's evidentiary standard applies: report what the runs showed, including — especially — when the intervention made things worse.

## Hypothesis

**H4 (prompt-engineering claim):** Two targeted prompt edits — a "must call a search tool before answering" directive in `VARIANT_SYSTEM`, and worked-example AST kinds in the `find_ast_pattern` schema — lift `qwen-max`'s hit rate on the 2-case calibration corpus from 25% to ≥50%, without regressing the rounds where it already succeeded.

The 2026-05-11 `qwen-max` n=4 run is the comparison: rounds 1+2 matched on semver, rounds 3+4 missed on semver, all four missed on follow-redirects.

**Result: H4 is rejected.** The hit rate did not rise to ≥50%; it fell to 0%, and the rounds that already succeeded *did* regress.

## Methodology

**Unchanged from 2026-05-11:**

- Harness: `npm run benchmark:variants-calibration -- --log-turns`
- Calibration cases: GHSA-c2qf-rxjj-qqgw (semver ReDoS, target band lines 138–161 of `internal/re.js`) and GHSA-cxjh-pqwp-8mfp (follow-redirects, target line 464 of `index.js`)
- Fixture commits: `2f738e9a` (semver vulnerable) and `8526b4a1` (follow-redirects vulnerable)
- Model: `qwen-max` via `--provider openai --base-url https://dashscope.aliyuncs.com/compatible-mode/v1`, credentials via `DASHSCOPE_API_KEY`
- Agent loop: `searchForVariants` in `src/analysis/variant-analyzer.ts`, MAX_TURNS=20
- Parser: post-[PR #60](https://github.com/mythos-agent/mythos-agent/pull/60) whole-text → fences → walk-from-end
- n=4, one `--results-subdir` per round

**Changed — the two edits under test (commit `313661c`):**

**Edit A** — a new section inserted into `VARIANT_SYSTEM`, between "Key Insight" and "Output Format":

```
## Workflow — REQUIRED

1. Identify the root cause from the CVE (one sentence in `rootCauseAnalysis`).
2. Call `find_ast_pattern` (or `search_code` if the AST kind is unclear) AT LEAST ONCE to find candidate sites in the codebase.
3. Only after a tool call has returned, emit your final JSON answer.

An empty `variants` array is a valid answer — but only AFTER step 2. Emitting `variants: []` without calling any search tool is treated as a failed run, not a "no variants found" result. Identifying the root cause is step 1; mechanically searching for instances of it is step 2. Do NOT skip step 2.
```

**Edit C** — the `find_ast_pattern` `kind` schema `description` in `src/agent/tools.ts`, replaced with a worked-example list keyed off "pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class" (5 example shapes: `template_string`, `array`/`string`, `binary_expression`, `new_expression`, `function_declaration`).

**Confirmation the edits reached the model.** Turn-1 `inputTokens` rose from yesterday's 1721 (semver) / 1694 (follow-redirects) to today's **1971 / 1944** — a uniform +250 tokens, the cost of the two edits. This rules out "the harness ran the old prompt": the new text was in every request.

## Runs

Eight rounds, two cases each — 16 case-runs. Every per-case `summary.json` reports `matched: false`.

| Round | Semver (GHSA-c2qf-rxjj-qqgw) | follow-redirects (GHSA-cxjh-pqwp-8mfp) | Combined |
| ----- | ---------------------------- | -------------------------------------- | -------- |
| 1     | miss — 1-turn give-up (4.2s) | miss — 1-turn give-up (2.7s)           | 0/2      |
| 2     | miss — 1-turn give-up (3.0s) | miss — 1-turn give-up (2.2s)           | 0/2      |
| 3     | miss — 1-turn give-up (2.4s) | miss — 1-turn give-up (2.5s)           | 0/2      |
| 4     | miss — 1-turn give-up (2.6s) | miss — 1-turn give-up (1.7s)           | 0/2      |

**Total: 0/8 (0% hit rate).**

Every case-run has the identical turn log shape:

```json
{"turn":1,"stopReason":"end_turn","toolCalls":[],
 "textPreview":"{ \"rootCauseAnalysis\": \"...correct...\", \"variants\": [] }"}
```

No round reached turn 2. No round called any tool. Wall time per case was 1.7–4.2s — consistent with a single LLM round-trip and no agent loop. (Yesterday's *successful* rounds took 35–74s because they ran a `find_ast_pattern` call and then emitted a 9-variant turn-2 answer.)

The `rootCauseAnalysis` field was correct in all 8 runs — the model still identifies ReDoS-via-template-literal on semver and the unstripped-`Proxy-Authorization`-header flaw on follow-redirects. Step 1 of the workflow directive is followed. **Step 2 — the mandatory tool call — is skipped in 8/8 runs**, the precise behavior the directive's closing line ("Do NOT skip step 2") forbids.

### Baseline vs. today, by failure mode

| | 2026-05-11 baseline | 2026-05-12 Bundle A+C |
| --- | --- | --- |
| MATCH | 2/8 (R1+R2 semver) | **0/8** |
| A — 1-turn give-up | 2/8 | **8/8** |
| B — over-escaped predicate | 1/8 | 0/8 |
| C — wrong AST `kind` | 3/8 | 0/8 |

The B and C counts dropped to zero not because the edits fixed them, but because **B and C are downstream of a tool call** — they describe *how* a `find_ast_pattern` call was malformed. With zero tool calls today, neither can occur. The entire 8/8 collapsed onto mode A.

## Attribution

The bundle's design assumed fixes A and C were independent and could be attributed separately from the turn logs. That assumption broke:

- **Fix A backfired.** The directive intended to *prohibit* the 1-turn give-up instead made it universal: mode A went 2/8 → 8/8. The two rounds that matched yesterday (R1, R2 semver) — which already followed the exact "one tool call, then answer" pattern the directive describes as correct — now give up on turn 1. The intervention did not merely fail to help the give-up rounds; it converted the working rounds into give-up rounds.

- **Fix C is unobservable.** Fix C only has an effect if the model calls `find_ast_pattern` and picks a `kind`. The model called no tools in any of the 8 runs. The new `kind` description was loaded into the prompt (the +250-token delta includes it) but never reached a decision point. **A's failure is upstream of C and masked it entirely.** We learned nothing about whether the worked-example `kind` list helps.

This is the experiment's main methodological lesson: A and C were bundled as if parallel, but they are *sequential* — A governs whether a tool call happens, C governs the shape of that call. Bundling a loop-entry fix with a loop-internal fix means a regression in the first makes the second untestable. A future round must validate A in isolation before C can be measured.

### Why did fix A backfire?

n=8 on one prompt variant cannot prove a mechanism, but two hypotheses are consistent with the data, and both point the same direction:

1. **Negative example as positive prime.** The directive contains the literal string `variants: []` twice ("An empty `variants` array…", "Emitting `variants: []` without calling any search tool…"), spelling out the exact give-up JSON it is trying to forbid. For a model already disposition-prone to short-circuit (the 2026-05-11 writeup measured this), embedding the give-up output verbatim in the system prompt plausibly acts as a one-shot demonstration of the give-up shape. Negative instructions that quote the forbidden output are a known prompt-engineering footgun on weaker models; the universal regression — including of previously-working rounds — fits this better than a partial effect would.
2. **Procedural list executed as 1→3.** The numbered "1. root cause → 2. tool call → 3. emit JSON" recipe may be read by `qwen-max` as "do step 1, then step 3," treating step 2's prose as skippable scaffolding. The directive's "Do NOT skip step 2" sentence did not prevent this in any of 8 runs.

We cannot isolate which sub-feature of edit A is responsible — the verbatim `variants: []` quotes, the numbered list, the "treated as a failed run" framing, or the added prompt length itself. That isolation is a follow-up, not a claim of this writeup.

## What this proves about the kill criterion

Quoted verbatim from [`docs/path-forward.md`](../path-forward.md):

> **Kill criteria:** if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough. At that point, the next bet is Track C (differential fuzzing), not deeper Track A iteration.

The kill criterion gates on "a serious attempt at the AST matcher." Today's 0/8 was **not** a serious attempt — the model never invoked the matcher, because a prompt edit *prevented* it from entering the agent loop. The 2026-04-27 Sonnet 4.6 run already cleared the kill criterion, and the 2026-05-11 `qwen-max` rounds 1+2 cleared it on the rounds that ran the matcher. Today's result is a property of one bad prompt edit on one model, not of the variants v2 design or its AST matcher.

**Conclusion: today's data does not trigger the kill criterion.** The 2026-10-26 kill date is unchanged. What today sharpens is the cost model for prompt engineering on `qwen-max`: it is not a free lever. A naive "force tool use" directive made the model strictly worse, including on inputs it previously handled correctly.

## What this writeup deliberately does not claim

- **"Forcing tool use is impossible on `qwen-max`."** One prose-directive variant failed. SDK-level `tool_choice: "any"` forcing (deliberately out of scope here to stay provider-agnostic) was never tested, and a directive that does not quote the give-up output verbatim was never tested. The space of "make `qwen-max` call a tool" edits is barely sampled.
- **"Fix C is wrong."** Fix C was not evaluated — the model never called `find_ast_pattern`. The worked-example `kind` list may help or may not; this run produced zero evidence either way.
- **"The negative-prime hypothesis is the cause."** It is the best-supported of two hypotheses at n=8 on one prompt. Mechanism attribution requires the isolation runs in Next Steps.
- **"`qwen-max` got worse as a model."** The model, fixtures, harness, and corpus are identical to 2026-05-11. The only changed variable is the prompt. The regression is the edit's, not the model's.
- **"Variants v2 regressed."** `main` is unchanged. The edits live only on branch `qwen-prompt-eng-bundle-ac` and are not merged. The Sonnet 4.6 path and the unedited `qwen-max` path both still behave as the 2026-05-11 writeup documented.
- **mythos-agent has found a 0-day.** Unchanged from every prior writeup: all calibration cases are known CVEs on known vulnerable commits.

## Cost

| Item | Rounds | Provider | API cost |
| ---- | ------ | -------- | -------- |
| `qwen-max` Bundle A+C n=4 | 4 | DashScope (free tier) | \$0 |

**Total today: \$0.** Wall time ≈ 30s across all 8 case-runs (every run short-circuited to one turn).

Research-arc cost to date: ~\$23 of Anthropic API credit (2026-04-26 v1 negative result + 2026-04-27 v2 first match) + \$0 across both Qwen writeups (2026-05-11 and today) = ~\$23 across four writeups.

## Reproducibility

```bash
git clone https://github.com/mythos-agent/mythos-agent
cd mythos-agent
git checkout 313661c   # Bundle A+C prompt edits
npm install

export DASHSCOPE_API_KEY="sk-..."

# qwen-max n=4, Bundle A+C
for i in 1 2 3 4; do
  npm run benchmark:variants-calibration -- \
    --provider openai --model qwen-max \
    --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
    --results-subdir "2026-05-12-qwen-max-round$i" \
    --log-turns
done
```

For Alibaba Cloud International accounts, replace the base URL with `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`.

Per-round results land in `benchmarks/variants-calibration/results/2026-05-12-qwen-max-round{1..4}/`. Each directory has `summary.json`, two `<GHSA>.json` result files, and two `<GHSA>.turns.jsonl` diagnostic logs.

**Branch / SHA:** `qwen-prompt-eng-bundle-ac` at `313661c` (Bundle A+C prompt edits). Baseline for comparison: `0abdeb8` (`main`, post-PR #60).

**Expected variance:** the agent loop is non-deterministic, but today's signal was unusually clean — 8/8 identical 1-turn give-ups. The headline (regression to 0/8 under this directive) is what to expect on reproduction; the specific `rootCauseAnalysis` wording will differ run-to-run.

## Next steps

In priority order:

1. **Do not merge Bundle A+C.** The branch stays unmerged; `main` keeps the 2026-05-11 prompt. Shipping the directive as-is would regress `qwen-max` and risks regressing other models for no measured benefit.
2. **Isolate fix A's mechanism (\$0, `qwen-max` free tier).** Run n=4 each on two A-variants: (a) the directive with the verbatim `variants: []` quotes removed and replaced with a non-output phrasing ("a result with no findings"); (b) the directive collapsed to a single imperative sentence with no numbered list. If (a) recovers and (b) does not, the negative-prime hypothesis holds; if (b) recovers, the procedural-list hypothesis holds.
3. **Test fix C in isolation, only after a working A.** Fix C never ran today. Once an A-variant restores tool calls at ≥ yesterday's rate, layer C on and re-run n=4 to get the follow-redirects `kind` signal the bundle was meant to produce.
4. **Consider SDK-level `tool_choice` forcing as the A alternative.** A prose directive is provider-agnostic but evidently fragile on `qwen-max`. Forcing the first turn to be a tool call via the OpenAI-compat `tool_choice` parameter sidesteps the disposition problem entirely — at the cost of provider-specific code. Worth a scoped spike if step 2's prompt-only variants also fail.
5. **Sonnet 4.6 n=4 reliability runs (~\$10–15).** Still the cheapest hard data point against the 2026-10-26 kill date, and still unaddressed. Carried forward from the 2026-05-11 next-steps list.

## See also

- [`docs/research/2026-05-11-variants-v2-model-portability.md`](2026-05-11-variants-v2-model-portability.md) — the `qwen-max` 2/8 baseline this experiment targeted and regressed against.
- [`docs/research/2026-04-27-variants-v2-first-match.md`](2026-04-27-variants-v2-first-match.md) — the Sonnet 4.6 origin run.
- [`docs/research/2026-04-26-variant-hunt-experiment.md`](2026-04-26-variant-hunt-experiment.md) — the variants v1 negative result that motivated Track A.
- [`docs/superpowers/specs/2026-05-12-qwen-prompt-engineering-design.md`](../superpowers/specs/2026-05-12-qwen-prompt-engineering-design.md) — the pre-registered Bundle A+C design, including the success/regression/kill bands this writeup reads against.
- [`docs/path-forward.md`](../path-forward.md) — Track A sub-PR breakdown and kill-criterion ladder.
- [PR #61](https://github.com/mythos-agent/mythos-agent/pull/61) — the 2026-05-11 writeup PR; this experiment is item 2 of its next-steps list.
