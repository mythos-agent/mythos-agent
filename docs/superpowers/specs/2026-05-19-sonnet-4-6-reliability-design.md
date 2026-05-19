# Design — Sonnet 4.6 n=4 reliability experiment

**Date:** 2026-05-19
**Issue trail:** next-steps item carried since `docs/research/2026-05-11-variants-v2-model-portability.md`; [issue #48](https://github.com/mythos-agent/mythos-agent/issues/48) Track A.
**Status:** approved, executed.

## TL;DR

Run the variants-calibration harness n=4 with Claude Sonnet 4.6 on the 2-case corpus to replace the shaky n=1 "2/2" baseline with a real reliability figure. No code changes — the harness already defaults to `claude-sonnet-4-6`. Single arm, default prompt, run on `main`. Write up `docs/research/2026-05-19-sonnet-4-6-reliability.md`.

## Background — why the baseline is shaky

The cited Sonnet "2/2" is n=1 and partly inferred. The 2026-04-27 runs recorded `2026-04-27-final` = 1/2 (semver miss, follow-redirects hit) and `2026-04-27-post-fix` = 0/2. The 2026-05-11 writeup reports "2/2" because PR #60's parser fix (shipped 2026-05-10) would recover the semver case from a parser-loss false-miss — but that 2/2 was never cleanly re-run post-PR-#60. Every qwen writeup since has carried "Sonnet n=4 reliability runs" as a next-steps item, deferred because the qwen-max prompt-engineering thread (PRs #62/#63/#64) took priority. That thread is now closed.

## Hypothesis

**H7 (reliability claim):** Sonnet 4.6 on the post-PR-#60 `main`, same harness/prompts/tools/fixtures/cases as the 2026-04-27 run, produces ≥1 hit per round across n=4, and reproduces the inferred 2/2 per round.

## Scope

### In scope

1. Run n=4 Sonnet 4.6 calibration: `--provider anthropic --model claude-sonnet-4-6`, 4 rounds, `--results-subdir 2026-05-19-sonnet-round{1..4}`, `--log-turns`.
2. Same 2 cases (GHSA-c2qf-rxjj-qqgw + GHSA-cxjh-pqwp-8mfp), same fixture commits, MAX_TURNS=20, same parser.
3. Analyze per-round hit rate, variant counts, tool-use depth; compare to the 2026-04-27 baseline and the qwen-max rows.
4. Publish `docs/research/2026-05-19-sonnet-4-6-reliability.md`.

### Out of scope

- **Code changes.** The harness already defaults to `claude-sonnet-4-6`; this is a pure measurement run. No spec→plan→implement cycle.
- **A/B arms.** Single arm — a reliability measurement, not a comparison.
- **qwen re-runs.** The qwen-max thread is closed (PRs #62/#63/#64).
- **A4 (unknown-variant hunt).** The real test against unknown variants is the *next* experiment this unblocks, not this one.

## Protocol

```bash
export ANTHROPIC_API_KEY=sk-ant-...
for i in 1 2 3 4; do
  npm run benchmark:variants-calibration -- \
    --provider anthropic --model claude-sonnet-4-6 \
    --results-subdir "2026-05-19-sonnet-round$i" --log-turns
done
```

Run on branch `sonnet-reliability-n4` (off `main`, code-identical) — no qwen experiment machinery, so no env-var contamination.

## Success / kill bands

- **Strong:** 7–8/8 — Sonnet reliably ≥1/round; the 2/2 was real; variants v2 is solid on the frontier model.
- **Moderate:** 4–6/8 — works but with qwen-like variance; the 2/2 was a lucky draw.
- **Weak:** ≤3/8 — Sonnet is also unreliable; the design has a deeper problem.

**Kill criterion (`docs/path-forward.md`):** the 2026-04-27 run already cleared it. This experiment sharpens the reliability picture; it does not move the 2026-10-26 kill date.

## Cost

~$10–15 estimated of Anthropic credit (Sonnet runs a deep multi-turn loop; ~5 min/case). First experiment in this arc to use paid credit rather than DashScope's free tier.

## Reproducibility note

Anthropic's API is region-restricted; from a restricted region the harness needs an outbound proxy. Node 22's native `fetch` does not honor `HTTP_PROXY`/`HTTPS_PROXY` by default — set `NODE_USE_ENV_PROXY=1` so the `@anthropic-ai/sdk` routes through the proxy. Without it the run fails fast with a non-Anthropic `403 "Request not allowed"`.

## See also

- `docs/research/2026-05-11-variants-v2-model-portability.md` — the n=1 Sonnet baseline and the model-portability table this experiment extends.
- `docs/research/2026-04-27-variants-v2-first-match.md` — the original Sonnet first-match run.
- `docs/path-forward.md` — Track A sub-PR sequence and kill criteria.
