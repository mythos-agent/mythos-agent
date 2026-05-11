# Variants v2 — Model-Portability Reliability Probe — 2026-05-11

> **TL;DR.** Eight calibration rounds on Alibaba Qwen via the OpenAI-compat adapter (`--provider openai --base-url https://dashscope.aliyuncs.com/compatible-mode/v1`). `qwen-plus` n=4: **0/8 hits** — model gives up in 1–2 turns and emits empty `variants` arrays without serious exploration. `qwen-max` n=4: **2/8 hits** (25%) — design works when the model commits to a real agent loop, but the model commits to one only half the time; rounds 1+2 both produced a clean MATCH on semver (5 variants in target band each), rounds 3+4 missed via three distinct failure modes (1-turn give-up, over-escaped predicate, wrong AST `kind`). Compared against the 2026-04-27 Sonnet 4.6 n=1 baseline (2/2 after [PR #60](https://github.com/mythos-agent/mythos-agent/pull/60)'s parser fix), the variants v2 design is **model-portable to a stronger Qwen tier in principle, but with a major reliability hit** that prompt-engineering — not a model swap to an even larger Qwen — is the cheapest path to close. Total cost: **\$0** (DashScope free tier).

## Why this writeup exists

The [2026-04-27 first-match writeup](2026-04-27-variants-v2-first-match.md) documented one Sonnet 4.6 run that produced 1/2 matched (lifted to 2/2 by [PR #60](https://github.com/mythos-agent/mythos-agent/pull/60), which fixed the parser-loss bug on the semver case). That run was **n=1**: a single calibration pass on a single model.

Two questions follow from that data:

1. **Reliability** — is 2/2 stable across re-runs, or did we catch a lucky one?
2. **Model portability** — does variants v2 work on anything other than the Anthropic frontier model we wired it against in [PR #50–#58](https://github.com/mythos-agent/mythos-agent/pulls?q=is%3Apr+%2350..%2358+is%3Aclosed)?

Today's experiment answers (2) on the cheap by running n=4 on two Qwen tiers via the existing `--provider openai` wiring from [PR #44/#46](https://github.com/mythos-agent/mythos-agent/pulls?q=is%3Apr+%2344+OR+%2346). Question (1) — Sonnet reliability — remains unanswered; this writeup is honest about why (we chose the free path today).

The 2026-04-26 negative-result writeup's evidentiary standard applies here too: report what the runs actually showed, including the failure modes, not just headline counts.

## Hypothesis

**H3 (model-portability claim):** With the same harness, prompts, tools, fixtures, and calibration cases as the 2026-04-27 Sonnet 4.6 run, variants v2 produces ≥1 hit per round on a comparable-tier non-Anthropic model.

The 2026-04-27 baseline was the same single run, the same two cases, the same target bands. The variable on the table today is the model.

## Methodology

**Unchanged from 2026-04-27:**

- Harness: `npm run benchmark:variants-calibration -- --log-turns`
- Calibration cases: GHSA-c2qf-rxjj-qqgw (semver ReDoS, target band lines 138–161 of `internal/re.js`) and GHSA-cxjh-pqwp-8mfp (follow-redirects, target line 464 of `index.js`)
- Fixture commits: `2f738e9a` (semver vulnerable) and `8526b4a1` (follow-redirects vulnerable)
- Agent loop: `searchForVariants` in `src/analysis/variant-analyzer.ts`, MAX_TURNS=20, system prompt forces JSON-only output
- Parser: post [PR #60](https://github.com/mythos-agent/mythos-agent/pull/60) — whole-text → fences → balanced-brace walk from end

**Changed:**

- Model: `qwen-plus` (mid-tier) and `qwen-max` (top tier) instead of `claude-sonnet-4-6`
- Provider path: `--provider openai --base-url https://dashscope.aliyuncs.com/compatible-mode/v1`, credentials via `DASHSCOPE_API_KEY` (resolved by `buildConfig` in `benchmarks/variants-calibration/run.ts`)
- n=4 instead of n=1 — four sequential rounds per model, one `--results-subdir` per round

## Runs

Eight rounds total, two cases each — 16 case-runs.

### qwen-plus (n=4)

| Round | Semver                                                             | follow-redirects                                | Combined |
| ----- | ------------------------------------------------------------------ | ----------------------------------------------- | -------- |
| 1     | miss (4.7s, 1 turn tools; 1 turn `end_turn` with empty `variants`) | miss (1.7s, 1 turn, no tools, empty `variants`) | 0/2      |
| 2     | miss (2.0s, same shape)                                            | miss (1.8s, same shape)                         | 0/2      |
| 3     | miss (2.0s, same shape)                                            | miss (1.7s, same shape)                         | 0/2      |
| 4     | miss (2.1s, same shape)                                            | miss (1.7s, same shape)                         | 0/2      |

**Total: 0/8.** Every round on every case ended in `end_turn` within ≤2 turns with `"variants": []`. The model identifies the root cause correctly in the `rootCauseAnalysis` field — round 1 follow-redirects emitted _"Incomplete stripping of sensitive headers during cross-origin redirects: the code removes 'Authorization' and 'Cookie' headers but fails to remove 'Proxy-Authorization'…"_ on its single turn without using any tools — but it never moves from the abstract root-cause sentence to a search of the codebase for matching variants.

The 1.7–4.7s wall times confirm this: a real 20-turn agent loop with tool calls takes 30+ seconds per case. qwen-plus is short-circuiting the loop.

### qwen-max (n=4)

| Round | Semver                                                                                             | follow-redirects                                                          | Combined |
| ----- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | -------- |
| 1     | **MATCH** — 9 variants, 5 in target band, 73.6s, 2 turns (1 `find_ast_pattern` call, 1 `end_turn`) | miss (7.4s, 1 `find_ast_pattern` call with wrong `kind=regex`, 0 results) | 1/2      |
| 2     | **MATCH** — 9 variants, 5 in target band, 35.6s, same 2-turn shape                                 | miss (6.6s, same wrong AST `kind`)                                        | 1/2      |
| 3     | miss (2.9s, 1-turn give-up like qwen-plus, no tools, empty `variants`)                             | miss (7.1s, wrong AST `kind`)                                             | 0/2      |
| 4     | miss (7.3s, 1 `find_ast_pattern` call with over-escaped predicate, 0 results)                      | miss (4.7s, 1-turn give-up)                                               | 0/2      |

**Total: 2/8 (25% hit rate).**

The hits — semver in rounds 1+2 — are structurally identical and clean. The variant list each round:

```
internal/re.js:122, 123, 138, 148, 155, 156, 160, 168, 173 (9 variants total)
                  ^^^^ ^^^^ ^^^^ ^^^^ ^^^^ ← 5 in calibration band (138-161)
```

The agent's `find_ast_pattern` call on the successful rounds:

```json
{
  "kind": "template_string",
  "text_predicates": ["\\\\s\\*|\\\\s\\+"],
  "file_glob": "**/*.js"
}
```

That correctly targets the template-literal regex builders A1's seed describes. JSON output was perfect — `text.trimStart().startsWith("{")` and `text.trimEnd().endsWith("}")`. The [PR #60](https://github.com/mythos-agent/mythos-agent/pull/60) walk-from-end parser fix was never exercised on Qwen output; the whole-text parse path handles it cleanly.

### The qwen-max failure-mode taxonomy

Three distinct misses across 8 case-runs on qwen-max:

1. **1-turn give-up (rounds 3 semver, 4 follow-redirects):** `end_turn` on turn 1 with `"variants": []` and a correct `rootCauseAnalysis`. Same disposition that defines qwen-plus. Wall time ≤5s. No tools called.

2. **Over-escaped predicate (round 4 semver):** the model called `find_ast_pattern` with `text_predicates: ["\\\\s\\*|\\\\s\\+", "\\${.*?}"]`. After JSON-decoding, the regex sent to the matcher is `\\s\*|\\s\+` — a literal-backslash search, which doesn't match the source-code `\s*`/`\s+` (one backslash). Returns 0 matches; agent concludes no variants exist. This is the same "tool was used correctly in spirit, broken in characters" failure that has bitten the 2026-04-27 run's semver T1 call before the prompt was tightened.

3. **Wrong AST `kind` (rounds 1–3 follow-redirects):** the model called `find_ast_pattern` with `{"kind": "regex", "text_predicates": ["^(?:authorization|cookie)$", "(?i)^(?!.*proxy-authorization).*"]}`. Reasonable in intent (find regex literals that include `authorization|cookie` and exclude `proxy-authorization`), but the follow-redirects fix is in an **array literal** of header names, not a regex AST node. The agent could have used `kind=array` or `kind=string` and gotten matches; it didn't, on three independent rounds.

The pattern: when `qwen-max` reasons correctly, it produces a clean MATCH. When it reasons incorrectly, it does so in _different_ ways round-to-round — there is no single bug to fix.

## Combined model picture

| Model                             | Rounds | Hits          | Semver                 | follow-redirects | Wall time                  | Tool-use depth                         |
| --------------------------------- | ------ | ------------- | ---------------------- | ---------------- | -------------------------- | -------------------------------------- |
| `claude-sonnet-4-6` (post PR #60) | 1      | **2/2**       | 1/1 + parser-recovered | 1/1 (line 464)   | 5 min/round                | 4 + 2 AST calls; 7 + 8 read_file       |
| `qwen-max`                        | 4      | **2/8** (25%) | 2/4                    | 0/4              | 6–80s/round, high variance | 1 AST call max; 0 reads, 0 search_code |
| `qwen-plus`                       | 4      | **0/8**       | 0/4                    | 0/4              | 1.7–4.7s/round             | ~0 tool calls per case                 |

The differentiator isn't model size in absolute terms — `qwen-max` is comparable to Sonnet on most public benchmarks — it's **agent-loop tenacity**. Sonnet uses 10+ turns and 20+ tool calls per case. `qwen-max` on its successful runs uses 1 AST call and ends. `qwen-plus` rarely uses tools at all.

## What this proves about the kill criterion

Quoted verbatim from [`docs/path-forward.md`](../path-forward.md):

> **Kill criteria:** if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough. At that point, the next bet is Track C (differential fuzzing), not deeper Track A iteration.

The kill criterion does not specify a model. Read strictly: the 2026-04-27 Sonnet 4.6 run already cleared it. Today's qwen-max 2/8 _also_ clears it on the rounds where the model committed to a serious attempt at the AST matcher (rounds 1+2 used `find_ast_pattern` correctly and produced ≥5 in-band candidates each).

**Conclusion: today's data does not trigger the kill criterion.** What it does is sharpen the framing — variants v2 isn't a model-agnostic black box; it's "frontier-model + structured root cause + AST tool" where each piece pulls weight. The 2026-10-26 kill date remains.

## What this writeup deliberately does not claim

- **Sonnet n=1 is the real number.** It isn't — Sonnet n=1 is one observation. The 2026-04-27 writeup acknowledged this; today's writeup adds Qwen rows without retiring the Sonnet uncertainty.
- **qwen-max 25% is the production rate.** It's the rate against this specific 2-case calibration corpus on this specific date. The follow-redirects 0/4 sub-result is consistent with a single root cause (wrong AST `kind`) that prompt engineering could plausibly fix.
- **`qwen-plus` can't do variant analysis.** It can't with this prompt and these tools. A more prescriptive prompt ("you MUST call `find_ast_pattern` at least 3 times before emitting your final answer") might lift it; we didn't test that.
- **Model size is the explanation.** `qwen-max` is comparable in headline benchmarks to Sonnet 4.6 but loops far less aggressively. The difference is disposition under tool-use instructions, not raw capability.
- **mythos-agent has found a 0-day.** Same as the 2026-04-27 writeup: all calibration cases are known CVEs on known vulnerable commits. A4 — the real test against unknown variants — is still pending.

## Cost

| Model       | Rounds | Provider              | API cost |
| ----------- | ------ | --------------------- | -------- |
| `qwen-plus` | 4      | DashScope (free tier) | \$0      |
| `qwen-max`  | 4      | DashScope (free tier) | \$0      |

**Total today: \$0.** Wall time ≈ 1 hr across all 8 rounds.

The combined research-arc cost to date: ~\$23 of Anthropic API credit (2026-04-26 v1 negative result + 2026-04-27 v2 first match, both Sonnet) plus \$0 today (Qwen via free tier) = ~\$23 across three writeups.

## Reproducibility

```bash
git clone https://github.com/mythos-agent/mythos-agent
cd mythos-agent
git checkout 0abdeb8   # post-PR #60 main
npm install

export DASHSCOPE_API_KEY="sk-..."

# qwen-plus n=4
for i in 1 2 3 4; do
  npm run benchmark:variants-calibration -- \
    --provider openai --model qwen-plus \
    --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
    --results-subdir "2026-05-11-qwen-round$i" \
    --log-turns
done

# qwen-max n=4
for i in 1 2 3 4; do
  npm run benchmark:variants-calibration -- \
    --provider openai --model qwen-max \
    --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
    --results-subdir "2026-05-11-qwen-max-round$i" \
    --log-turns
done
```

For Alibaba Cloud International accounts, replace the base URL with `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`.

Per-round results land in `benchmarks/variants-calibration/results/2026-05-11-{qwen,qwen-max}-round{1..4}/`. Each directory contains `summary.json`, two per-case `<GHSA>.json` result files, and two `<GHSA>.turns.jsonl` diagnostic logs.

**Branch / SHA:** `main` at commit `0abdeb8` (post-PR #60 walk-from-end parser fix).

**Expected variance:** the LLM agent loop is non-deterministic. Today's `qwen-max` showed three distinct failure modes across 4 rounds (1-turn give-up, over-escaped predicate, wrong AST `kind`) and two semver hits with identical 9-variant output — the specifics will not repeat exactly, but the order-of-magnitude hit rate (~25% on `qwen-max`, 0% on `qwen-plus`) is what to expect on reproduction.

## Next steps

In priority order:

1. **Sonnet 4.6 n=4 reliability runs (~\$10–15).** The Sonnet baseline is still n=1 — today's writeup widens the comparison axis but doesn't deepen the original observation. Three more Sonnet rounds would tell us whether 2/2 is stable or a lucky observation. Cheapest data point against the 2026-10-26 kill date.
2. **Prompt engineering for `qwen-max` aggressive-exploration.** The 25% hit rate is bounded by disposition, not capability — rounds 1+2 prove the model CAN find variants when it commits. A "MUST call `find_ast_pattern` at least N times before answering" directive in the system prompt is the cheapest experiment. Re-run n=4 with the new prompt; if hit rate lifts past 50%, variants v2 is genuinely model-portable.
3. **`find_ast_pattern` prompt scaffolding for non-regex root causes.** The follow-redirects 0/4 sub-result on `qwen-max` traces to the agent picking `kind=regex` when the fix is in an array literal. The tool's documentation (in the agent's tool schema) doesn't currently illustrate non-regex root causes well. Adding 1–2 worked-example shapes (`kind=array_pattern`, `kind=binary_expression`) to the schema description might close this gap without touching the model at all.
4. **A4 — the variant-hunt experiment re-run.** Same 4 targets and 2 seeds as the [2026-04-26 writeup](2026-04-26-variant-hunt-experiment.md), but with A1 + A2 + A3 in place and Sonnet 4.6 as the model (the only one with a stable per-round hit pattern so far). Goal: ≥1 verified-real candidate across 8 runs vs. the 0/8 v1 baseline. This is the actual test against unknown variants and the natural next paid expenditure.

## See also

- [`docs/research/2026-04-26-variant-hunt-experiment.md`](2026-04-26-variant-hunt-experiment.md) — the variants v1 negative result that motivated Track A.
- [`docs/research/2026-04-27-variants-v2-first-match.md`](2026-04-27-variants-v2-first-match.md) — the variants v2 Sonnet 4.6 baseline this writeup compares against.
- [`docs/path-forward.md`](../path-forward.md) — Track A sub-PR breakdown (A1 → A4) and kill-criterion ladder.
- [`docs/multi-model.md`](../multi-model.md) — multi-model adapter that enabled today's free Qwen path.
- [PR #60](https://github.com/mythos-agent/mythos-agent/pull/60) — walk-from-end parser fix (shipped 2026-05-10, prerequisite for today's `qwen-max` whole-text parse path).
