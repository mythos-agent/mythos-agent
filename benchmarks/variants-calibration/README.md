# Variants v2 calibration harness (A3b)

Live, agent-driven calibration runner for sub-PR A3b of issue #48 / Track A in
[`docs/path-forward.md`](../../docs/path-forward.md). Where
[`benchmarks/cve-replay/`](../cve-replay/) runs the deterministic scanner
pipeline, and `src/analysis/calibration/` (A3a) runs A2's matcher offline,
this harness drives the **full variant-analyzer agent loop** against the
upstream vulnerable code.

## What it does

For each CVE Replay case that has a `calibration_target` in
[`../cve-replay/cases/`](../cve-replay/cases/) (currently the 2/5 caught:
semver CVE-2022-25883 and follow-redirects CVE-2024-28849):

1. Clone the upstream repo to `fixtures/<ghsa>/` (or reuse an existing clone).
2. Check out the `vulnerable_commit`.
3. Build an enriched `CveInfo` whose `rootCause` field carries A1's structured
   seed pattern (bug class, CWE, AST shape kind + constraints, data flow). The
   variant-analyzer prompt threads this in as the "root cause" the LLM was
   already asked to extract — but pre-extracted, so the model short-circuits
   to step 2 (search).
4. Run `VariantAnalyzer.searchForVariants` (the same loop the
   `mythos-agent variants` CLI command uses), with `find_ast_pattern` from A2
   automatically available to the agent.
5. Check whether any returned variant's `file:line` overlaps the case's
   `calibration_target.lines` band.
6. Write per-case JSON results to `results/<timestamp>/<ghsa>.json` plus a
   `summary.json` for the run.

## Cost

This harness performs **paid LLM calls**. Each case is one full
variant-analyzer loop (capped at 20 turns). Empirically that's **\$0.50–\$2
per case** with Claude Sonnet 4.6 — see
[`docs/research/2026-04-26-variant-hunt-experiment.md`](../../docs/research/2026-04-26-variant-hunt-experiment.md)
for the prior order-of-magnitude data. With 2 calibration cases, expect
**\$1–\$4 per full run**.

## How to run

```sh
# Anthropic (default)
ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration

# A single case, OpenAI-compat backend
OPENAI_API_KEY=sk-... npm run benchmark:variants-calibration -- \
  --case GHSA-c2qf-rxjj-qqgw --provider openai --model gpt-4o

# Force a stable results subdir name (instead of an ISO timestamp)
ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration -- \
  --results-subdir 2026-04-26-claude-sonnet-4-6
```

The first run clones the upstream repos; subsequent runs reuse the clones
and just re-fetch the vulnerable commit if needed.

## What "matched" means

A case is matched when the agent returns at least one variant whose `file`
ends with the case's `calibration_target.file` AND whose reported `line` is
within the target band (inclusive). The variant-analyzer reports a single
`line` per variant, not a range, so the overlap check is line-against-band
rather than range-against-range. See
[`src/analysis/calibration/agent-runner.ts`](../../src/analysis/calibration/agent-runner.ts)
for the exact predicate.

## Kill criterion

Per [`docs/path-forward.md`](../../docs/path-forward.md): if A3 (calibration
on known cases) produces 0 candidates after a serious attempt at the AST
matcher, the structured-root-cause approach also isn't enough. The next bet
in that case is Track C (differential fuzzing), not deeper Track A iteration.
The pre-committed kill date is **2026-10-26**.

A3a (deterministic, offline — `npm test` covers `src/analysis/calibration/`)
already shows the matcher hits both targets. A3b (this harness) is what
proves the *agent* can land on the right candidate, not just the matcher.

## Output

```
benchmarks/variants-calibration/results/<run-id>/
  GHSA-c2qf-rxjj-qqgw.json    # full per-case AgentCalibrationResult
  GHSA-cxjh-pqwp-8mfp.json
  summary.json                 # { runAt, config, results: [{ghsa, matched, ...}] }
```

Promote interesting runs to `docs/research/<date>-variants-calibration-<model>.md`
following the
[2026-04-26 variant-hunt experiment](../../docs/research/2026-04-26-variant-hunt-experiment.md)
format.
