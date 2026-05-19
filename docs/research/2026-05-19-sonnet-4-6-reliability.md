# Variants v2 — Sonnet 4.6 Reliability Probe (n=4) — 2026-05-19

> **TL;DR.** The variants v2 design has been carried on a Sonnet "2/2" that was always n=1 — and partly *inferred*: the 2026-04-27 runs actually recorded `2026-04-27-final` = 1/2 and `2026-04-27-post-fix` = 0/2; the cited 2/2 assumes PR #60's parser fix recovers the semver case, and was never cleanly re-run post-PR-#60. This experiment runs Claude Sonnet 4.6 n=4 on the same 2-case calibration corpus to settle it. **Result: 8/8 — every case-run matched, all four rounds 2/2, zero misses, zero errors.** The inferred 2/2 is now confirmed real and stable. Sonnet ran a deep agentic loop — 10.8 turns and 18.3 tool calls per case on average, all four tools used — the exact behavior the three qwen-max writeups identified as the differentiator (qwen-max gets ≤1 tool call before answering). Hit *outcome* was rock-solid across n=4; only variant count (semver 9–12, always 5 in the calibration band) and wall time (39–290 s) varied. Recorded token usage ≈ \$3 at list price, well under the \$10–15 budget. This is the cheapest hard data point against the 2026-10-26 kill date, and it clears cleanly.

## Why this writeup exists

Every Qwen writeup since 2026-05-11 has carried "Sonnet 4.6 n=4 reliability runs" as a next-steps item, deferred while the qwen-max prompt-engineering thread ran. That thread is now closed — three experiments ([PR #62](https://github.com/mythos-agent/mythos-agent/pull/62), [#63](https://github.com/mythos-agent/mythos-agent/pull/63), [#64](https://github.com/mythos-agent/mythos-agent/pull/64)) established that qwen-max's agent loop is too shallow to use the variants v2 design reliably, and that the cheap prompt levers are exhausted. The open question the whole arc kept deferring: **is the Sonnet baseline — the model the design was built against — actually reliable, or did 2026-04-27 catch a lucky single run?**

The honesty problem is concrete. The 2026-05-11 writeup's combined table lists "claude-sonnet-4-6 (post PR #60) — 1 round — 2/2", and its own non-claims section flagged it: "Sonnet n=1 is one observation." Worse, the 2/2 is not even a clean observation — `benchmarks/variants-calibration/results/2026-04-27-final/` records semver=miss, follow-redirects=hit (1/2), and `2026-04-27-post-fix/` records 0/2. The "2/2" is 1 observed hit plus 1 semver hit *inferred* from the [PR #60](https://github.com/mythos-agent/mythos-agent/pull/60) parser fix (shipped 2026-05-10) recovering a parser-loss false-miss. It was never re-run after PR #60 landed. This experiment replaces all of that with n=4 measured data.

## Hypothesis

**H7 (reliability claim):** Sonnet 4.6 on the post-PR-#60 `main` — same harness, prompts, tools, fixtures, and cases as the 2026-04-27 run — produces ≥1 hit per round across n=4, and reproduces the inferred 2/2 per round.

**Result: H7 holds, at the ceiling.** Not ≥1 per round — *2/2 every round*, 8/8 overall.

## Methodology

- Harness: `npm run benchmark:variants-calibration -- --log-turns`
- Model: `claude-sonnet-4-6` via `--provider anthropic` (the harness default model; no code change needed)
- Cases: GHSA-c2qf-rxjj-qqgw (semver ReDoS, target band lines 138–161 of `internal/re.js`) and GHSA-cxjh-pqwp-8mfp (follow-redirects, target line 464 of `index.js`), fixture commits `2f738e9` and `8526b4a`, MAX_TURNS=20, post-PR-#60 parser
- n=4, one `--results-subdir` per round, on branch `sonnet-reliability-n4` (off `main` at `8e9df47` — code-identical to `main`, no qwen experiment machinery)
- Single arm — a reliability measurement, not an A/B

This is a pure measurement: nothing in `src/` changed. The only deviation from a naive run was an environment fix — see Reproducibility.

## Runs

8 case-runs (4 rounds × 2 cases). `variants` = total candidates emitted; `in band` = candidates inside the calibration target range.

| Round | semver — result | follow-redirects — result |
| --- | --- | --- |
| 1 | **MATCH** — 12 variants, 5 in band, 290 s, 15 turns / 23 tool calls | **MATCH** — 1 variant, 1 in band, 65 s, 9 turns / 12 tool calls |
| 2 | **MATCH** — 9 variants, 5 in band, 146 s, 10 turns / 19 tool calls | **MATCH** — 1 variant, 1 in band, 281 s, 14 turns / 23 tool calls |
| 3 | **MATCH** — 12 variants, 5 in band, 257 s, 11 turns / 19 tool calls | **MATCH** — 1 variant, 1 in band, 39 s, 7 turns / 12 tool calls |
| 4 | **MATCH** — 11 variants, 5 in band, 187 s, 9 turns / 17 tool calls | **MATCH** — 1 variant, 1 in band, 123 s, 11 turns / 21 tool calls |

**Total: 8/8. Every round 2/2. Zero misses, zero errors.**

Aggregate tool use: 86 turns and 146 tool calls across the 8 case-runs — **10.8 turns and 18.3 tool calls per case-run**, drawing on all four tools (`read_file`, `search_code`, `find_ast_pattern`, `list_files`). Recorded usage: 760.8K input + 28.2K output tokens.

## Attribution

**The hit outcome is stable; the path to it is not.** All 8 case-runs hit — that is the reliability result. But the runs are visibly non-deterministic underneath: semver emitted 9–12 variants round to round (always exactly 5 inside the 138–161 band), wall time ranged 39–290 s, and tool-call depth ranged 12–23. Sonnet reaches the answer by a different route each time and still lands it every time. That is the desired property — robustness, not determinism.

**Depth is the differentiator, and the n=4 data confirms it cleanly.** The three qwen writeups argued that variants v2 needs a model that *commits to the agent loop*: qwen-max, on its successful runs, used a single `find_ast_pattern` call and stopped; qwen-plus rarely called tools at all. Sonnet here averages 10.8 turns and 18.3 tool calls per case — it lists files, greps, reads candidate files, runs AST queries, reads more, and only then answers. The semver case (290 s / 23 tool calls in round 1) shows the loop working hard. This is not a model-size story — qwen-max is benchmark-comparable to Sonnet — it is an agent-loop-disposition story, and Sonnet has the disposition.

**The follow-redirects case is the cleanest signal.** It hit 4/4 here, always with exactly 1 in-band variant at the target line. That is the case qwen-max missed 0/4 → 0/8 across every qwen experiment (mode C: `kind: "regex"` on a fix that lives in an array literal). Sonnet's deeper loop — `search_code` 3–7 times per follow-redirects run, plus `read_file` 5–12 times — finds the header-array site that qwen-max's single mis-typed AST query never reached.

**Same-session, same code.** Both calibration cases, both fixture commits, the post-PR-#60 parser, MAX_TURNS=20 — all identical to 2026-04-27. The only changed variable from that run is the passage of time and a clean n=4 instead of n=1. The 2/2 was real.

## What this proves about the kill criterion

Quoted verbatim from `docs/path-forward.md`:

> **Kill criteria:** if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough. At that point, the next bet is Track C (differential fuzzing), not deeper Track A iteration.

A3 calibration on known cases now produces candidates on 8/8 attempts, with a serious AST-matcher loop every time (avg 18.3 tool calls). The criterion is not merely cleared — it is cleared with no variance in the hit outcome across n=4. **The 2026-10-26 kill date stands, and Track A is not at risk on the calibration corpus.** What remains genuinely open is A4 — the test against *unknown* variants — which this experiment does not touch but does unblock (see Next steps).

## Updated model picture

| Model | Rounds | Hits | Loop depth (tool calls/case) | Notes |
| --- | --- | --- | --- | --- |
| `claude-sonnet-4-6` | **4** | **8/8** | ~18 | deep loop, hit outcome stable across n=4 |
| `claude-sonnet-4-6` (2026-04-27) | 1 | 2/2 (1 observed + 1 parser-inferred) | — | the shaky baseline this experiment replaces |
| `qwen-max` | 4 | 2/8 | ≤1 | 1-turn give-up / wrong AST kind / over-escaped predicate |
| `qwen-plus` | 4 | 0/8 | ~0 | rarely calls tools at all |

The 2026-05-11 framing holds and is now firmly evidenced: variants v2 is "frontier-model + structured root cause + AST tool," and the frontier model is doing real, necessary work — not a formality.

## What this writeup deliberately does not claim

- **"8/8 is the production hit rate."** It is the rate on this specific 2-case calibration corpus — known CVEs on known vulnerable commits, with target bands the design was tuned against. It is a *reliability* result (the design works repeatably on calibration cases), not a discovery rate.
- **"Sonnet is deterministic."** It is not — variant counts (9–12), wall times (39–290 s), and tool-call depth (12–23) varied every round. Only the hit/miss *outcome* was stable across n=4. n=4 is four observations, not a proof of zero future misses.
- **"This is the test against unknown variants."** It is not — see A4 in Next steps. All eight runs targeted known seeds on known vulnerable fixture commits.
- **"qwen-max is unusable."** Out of scope here; the qwen writeups stand on their own. This experiment compares only to contextualize Sonnet's depth.
- **mythos-agent has found a 0-day.** Unchanged from every prior writeup.

## Cost

| Item | Runs | Provider | Recorded tokens | API cost |
| --- | --- | --- | --- | --- |
| Sonnet 4.6 n=4 | 8 case-runs | Anthropic | 760.8K in / 28.2K out | ≈ \$3 (list price) |

The harness turn logs record only `inputTokens` / `outputTokens` — no prompt-cache breakdown — so the true cost is modestly higher than the ≈\$2.7 list-price computation once cache-read tokens are counted. Either way it came in **well under the \$10–15 budgeted**; the deep loop is cheaper per run than the conservative estimate assumed. Wall time ≈ 23 min across all 8 case-runs.

Research-arc cost to date: ~\$23 (2026-04-26 + 2026-04-27, Sonnet) + \$0 across four Qwen writeups + ~\$3–8 today ≈ **~\$30 across seven writeups**.

## Reproducibility

```bash
git clone https://github.com/mythos-agent/mythos-agent
cd mythos-agent
git checkout 8e9df47   # main, post-PR #60
npm install

export ANTHROPIC_API_KEY="sk-ant-..."

for i in 1 2 3 4; do
  npm run benchmark:variants-calibration -- \
    --provider anthropic --model claude-sonnet-4-6 \
    --results-subdir "2026-05-19-sonnet-round$i" --log-turns
done
```

**Region / proxy note.** Anthropic's API is region-restricted. From a restricted region the harness needs an outbound proxy — and Node 22's native `fetch` does **not** honor `HTTP_PROXY`/`HTTPS_PROXY` by default, so the `@anthropic-ai/sdk` request bypasses the proxy, connects directly, and fails fast with a non-Anthropic `403 {"error":{"type":"forbidden","message":"Request not allowed"}}`. Fix: `export NODE_USE_ENV_PROXY=1` (Node 22's built-in `EnvHttpProxyAgent` switch) so the SDK routes through the proxy your environment already defines. `curl` is unaffected — it honors the proxy env vars natively — so a working `curl` to `api.anthropic.com` next to a failing harness run is the signature of this issue.

Per-round results land in `benchmarks/variants-calibration/results/2026-05-19-sonnet-round{1..4}/`.

**Branch / SHA:** `sonnet-reliability-n4` at `8e9df47` (= `main`, post-PR-#60).

**Expected variance:** the hit outcome was 8/8 with no variance across n=4; expect that to reproduce. Variant counts, wall times, and tool-call depth will not reproduce exactly — the loop is non-deterministic.

## Next steps

In priority order:

1. **A4 — the variant-hunt against unknown variants, Sonnet 4.6.** This is the experiment the Sonnet reliability question was blocking. With 8/8 on calibration, the model choice for A4 is settled: Sonnet runs the loop reliably. A4 is the actual test of whether variants v2 finds *unknown* vulnerable code — the real bet, and the natural next paid expenditure. Same 4 targets / 2 seeds as the 2026-04-26 variant-hunt writeup, now with A1+A2+A3 in place.
2. **Nothing further on qwen-max.** The thread is closed (PRs #62/#63/#64). qwen-max is not a viable model for this design without an agent-loop overhaul, which is out of scope for Track A.
3. **Optionally, log prompt-cache tokens in the harness.** The turn logs currently omit cache fields, so cost figures are approximate. A small harness change would make future paid runs precisely costed — minor, do it only if more paid runs are planned.

## See also

- `docs/research/2026-05-11-variants-v2-model-portability.md` — the n=1 Sonnet baseline and model-portability table this experiment extends.
- `docs/research/2026-04-27-variants-v2-first-match.md` — the original Sonnet first-match run.
- `docs/research/2026-05-19-qwen-fix-c-on-variant-b.md` — the final qwen-max experiment; closes that thread.
- `docs/research/2026-04-26-variant-hunt-experiment.md` — the variants v1 negative result; A4 re-runs its targets.
- `docs/superpowers/specs/2026-05-19-sonnet-4-6-reliability-design.md` — the pre-registered design.
- `docs/path-forward.md` — Track A sub-PR sequence and kill criteria.
