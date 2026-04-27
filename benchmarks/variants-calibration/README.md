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
variant-analyzer loop (capped at 20 turns).

| Provider                           | Per-case cost | 2-case run |
| ---------------------------------- | ------------- | ---------- |
| Anthropic (Claude Sonnet 4.6)      | \$0.50–\$2    | \$1–\$4    |
| Qwen via DashScope (`qwen-plus`)   | \$0.05–\$0.30 | \$0.10–\$0.60 |

Numbers above are derived from the prior data in
[`docs/research/2026-04-26-variant-hunt-experiment.md`](../../docs/research/2026-04-26-variant-hunt-experiment.md)
(8-run experiment cost ~\$5–\$7 across both providers). Treat them as
order-of-magnitude estimates; actual cost depends on how many tool turns
the agent spends per case.

## How to run

```sh
# Anthropic (default — claude-sonnet-4-6)
ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration

# OpenAI / OpenRouter / vLLM / LM Studio (any OpenAI-compatible endpoint)
OPENAI_API_KEY=sk-... npm run benchmark:variants-calibration -- \
  --provider openai --model gpt-4o

# Qwen via Alibaba DashScope (Tier 2 path from docs/multi-model.md).
# Roughly an order of magnitude cheaper than Claude per the multi-model
# doc; per-case runs land in the ~$0.10–$0.50 range.
DASHSCOPE_API_KEY=sk-... npm run benchmark:variants-calibration -- \
  --provider openai --model qwen-plus \
  --base-url https://dashscope.aliyuncs.com/compatible-mode/v1

# A single case, stable results subdir name
ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration -- \
  --case GHSA-c2qf-rxjj-qqgw \
  --results-subdir 2026-04-26-claude-sonnet-4-6
```

`--base-url` can also be set via `MYTHOS_BASE_URL` or `OPENAI_BASE_URL`
env vars when shelling out from a script. `--help` prints the full
flag/env reference.

The first run clones the upstream repos; subsequent runs reuse the clones
and just re-fetch the vulnerable commit if needed.

## Diagnosing a 0-variants result with `--log-turns`

When a case completes with `matched: false, variantsFound: 0`, the result
JSON alone can't tell you whether the agent **reached for the seeded AST
pattern** (`find_ast_pattern`) and missed, or **never used it at all**
(stayed on regex `search_code`). That distinction matters for the kill
criterion: only the first is a real test of the structured-root-cause
design.

Pass `--log-turns` to write a per-turn JSONL log alongside each result:

```sh
ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration -- --log-turns
# results/<run-id>/
#   GHSA-c2qf-rxjj-qqgw.json        ← outcome (matched, variants, target)
#   GHSA-c2qf-rxjj-qqgw.turns.jsonl ← per-turn diagnostics (NEW)
```

Each line is one `messages.create` round-trip:

```jsonl
{"turn":1,"timestamp":"...","durationMs":4321,"stopReason":"tool_use",
 "toolCalls":[{"name":"find_ast_pattern","input":{"kind":"regex"}}],
 "textPreview":"I'll search for regex literals filtering headers...",
 "usage":{"inputTokens":1247,"outputTokens":89}}
{"turn":2,...}
```

Quick analysis recipes:

```sh
# Did the agent ever call find_ast_pattern?
jq -r '.toolCalls[].name' GHSA-cxjh-pqwp-8mfp.turns.jsonl | sort | uniq -c

# Total token spend per turn over a run:
jq -r '[.turn, .usage.inputTokens, .usage.outputTokens] | @tsv' *.turns.jsonl
```

The log captures stop reason, tool calls (name + input), a 400-char text
preview, and token usage. **It never contains your API key** — the wrapper
sits at the LLMClient interface boundary, where credentials are not
visible. Long tool inputs are truncated with an explicit `__truncated`
marker so a reader can tell "model emitted exactly this" from "we
shortened this on the way out."

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
