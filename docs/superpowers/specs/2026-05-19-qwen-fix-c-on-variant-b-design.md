# Design — fix C on variant-b's working loop

**Date:** 2026-05-19
**Issue trail:** [PR #63](https://github.com/mythos-agent/mythos-agent/pull/63) (fix-A isolation) next-steps item 2; [PR #62](https://github.com/mythos-agent/mythos-agent/pull/62) (Bundle A+C); [issue #48](https://github.com/mythos-agent/mythos-agent/issues/48) Track A.
**Status:** approved, pre-implementation.

## TL;DR

The 2026-05-19 fix-A isolation experiment found that the `variant-b` prompt arm (a single-sentence workflow directive, no numbered list) recovers qwen-max tool use to 8/8 — but follow-redirects still misses 4/4 via failure mode C: the model calls `find_ast_pattern` with `kind: "regex"` when the follow-redirects fix actually lives in an array literal of header strings. Fix C — the worked-example AST-`kind` schema description pre-registered in [PR #62](https://github.com/mythos-agent/mythos-agent/pull/62)'s Bundle A+C — was designed to correct exactly this, but has never been tested on a working loop: in the 2026-05-12 bundle, mode A killed the loop before any tool call; in the 2026-05-19 `control`/`variant-a` arms, the same. `variant-b` is the first working loop fix C can be measured on. This experiment adds an `MYTHOS_FIND_AST_KIND_DOC` env toggle to `src/agent/tools.ts`, holds the prompt at `variant-b`, and runs qwen-max n=4 on two arms — `(variant-b, baseline-C)` and `(variant-b, fix-C)` — then writes up `docs/research/2026-05-19-qwen-fix-c-on-variant-b.md`.

Goal: determine whether fix C's worked-example `kind` list moves qwen-max off `kind: "regex"` on the follow-redirects case.

## Background — what 2026-05-19 established

From `docs/research/2026-05-19-qwen-fix-a-isolation.md`, the `variant-b` arm (n=4, qwen-max):

- Turn-1 tool-call rate **8/8** — mode A (1-turn give-up) is gone.
- Hits **1/8** — recovering the loop did not recover accuracy.
- follow-redirects: **4/4 `kind: "regex"`**, 0 variants every time — mode C, reproducible.
- semver: 4/4 `kind: "template_string"` (correct kind), 1/4 hit — the 3 misses are mode B (over-escaped `text_predicates`).

So on `variant-b`, mode C is now a clean, reproducible 4/4 failure on follow-redirects. That is the target of this experiment.

## The fix-C edit

Fix C is the `find_ast_pattern` `kind` schema `description` from PR #62 commit `313661c`. Verbatim, the two versions:

**baseline-C** (current `src/agent/tools.ts`):

```
'tree-sitter node kind to match (e.g. "call_expression", "new_expression", "function_declaration", "regex", "template_string"). May be a single string or an array of strings for union matching.'
```

**fix-C** (PR #62 `313661c`):

```
"tree-sitter node kind to match. Pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class. Examples:\n" +
'- ReDoS in template-literal regex builders → kind: "template_string"\n' +
'- Header allowlist/denylist as inline strings → kind: "array" or "string" (NOT "regex" — the headers are array elements, not a regex literal)\n' +
'- Comparison flaw → kind: "binary_expression"\n' +
'- new RegExp(userInput) → kind: "new_expression"\n' +
'- Function declaration with a specific parameter name → kind: "function_declaration"\n' +
"May be a single string or an array of strings for union matching."
```

The second worked-example bullet targets the follow-redirects mode-C miss directly. Fix C is used **verbatim** from `313661c` — it is the pre-registered edit, and reusing it unchanged keeps attribution to "fix C as designed," not "a refined fix C."

## Hypothesis

**H6 (fix-C claim):** On qwen-max running the `variant-b` prompt, the fix-C worked-example `kind` schema moves the follow-redirects `find_ast_pattern` call off `kind: "regex"` toward `kind: "array"`/`"string"`, relative to the same-session `baseline-C` arm.

Decision logic, read within-session (baseline-C arm vs fix-C arm):

| Observation | Conclusion |
| --- | --- |
| fix-C picks non-`regex` kind on follow-redirects in a majority of runs | H6 supported — the worked-example list shifts qwen-max's `kind` choice |
| fix-C still picks `kind: "regex"` ≈ 4/4 | H6 rejected — the worked-example list does not change the choice; a schema description is the wrong lever |
| fix-C re-introduces mode A (turn-1 give-ups) or regresses semver's correct `kind: "template_string"` | fix C has a harmful side effect; report as a regression |

A non-`regex` `kind` choice is the primary success signal even if it does not produce a hit — moving the `kind` is fix C's job; whether the resulting matches then hit depends on `text_predicates` (mode B), which this experiment does not touch.

## Scope

### In scope

1. Add `MYTHOS_FIND_AST_KIND_DOC` env-var support to `src/agent/tools.ts`: a `resolveFindAstKindDoc(raw)` resolver and the two `kind`-description strings (`baseline`, `worked-examples`). Unset → `baseline` (current behavior). Unrecognized value → throw.
2. Wire the resolved description into the `find_ast_pattern` tool schema in `createAgentTools`.
3. Unit-test the resolver and the description selection.
4. Run qwen-max n=4 on two arms — `MYTHOS_VARIANT_PROMPT=variant-b` held constant, `MYTHOS_FIND_AST_KIND_DOC` ∈ {`baseline`, `worked-examples`}.
5. Compare follow-redirects `kind` choice and hit rate within-session; publish `docs/research/2026-05-19-qwen-fix-c-on-variant-b.md`.

### Out of scope

- **Mode B (over-escaped `text_predicates`).** fix C addresses `kind`, not predicates. The semver 3/4 mode-B misses are a separate lever; not touched here. One variable at a time.
- **The prompt dimension.** The prompt is held at `variant-b` for both arms — `variant-b` is the established working loop. `control`/`variant-a` are not re-run; they do not produce a reliable tool call for fix C to act on.
- **A refined or expanded fix C.** Fix C is used verbatim from `313661c`. Iterating on the worked-example wording is a possible follow-up, not this experiment.
- **qwen-plus, Sonnet 4.6.** One model. Sonnet n=4 reliability remains separately carried.
- **Merging prompt/tool changes to `main`.** Diagnostic experiment; promotion is a later decision.

## Implementation shape

All in `src/agent/tools.ts`.

- `type FindAstKindDoc = "baseline" | "worked-examples"`.
- Two module-level string constants: `KIND_DOC_BASELINE` and `KIND_DOC_WORKED_EXAMPLES`, holding the two descriptions verbatim as above.
- `resolveFindAstKindDoc(raw: string | undefined): FindAstKindDoc` — `undefined`/`""` → `"baseline"`; a recognized value → that value; anything else → `throw` naming the bad value and the valid set.
- In `createAgentTools`, the `find_ast_pattern` schema's `kind.description` is set to the constant selected by `resolveFindAstKindDoc(process.env.MYTHOS_FIND_AST_KIND_DOC)`.
- A one-line stderr log of the active doc, mirroring `variant-analyzer.ts`'s `[variant-analyzer] prompt variant: …` line — for per-run provenance.

This mirrors the `MYTHOS_VARIANT_PROMPT` mechanism from the fix-A isolation branch: env var, fail-loud resolver, stderr provenance line, default = unchanged behavior.

## Experimental protocol

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

- 2 arms × 4 rounds × 2 cases = 16 case-runs.
- Same cases (GHSA-c2qf-rxjj-qqgw + GHSA-cxjh-pqwp-8mfp), same fixture commits, MAX_TURNS=20, same parser.
- `MYTHOS_VARIANT_PROMPT=variant-b` held constant across both arms; `MYTHOS_FIND_AST_KIND_DOC` is the only variable.
- `DASHSCOPE_API_KEY` set by the user in their Git Bash window.

**Attribution via turn logs:** the primary signal is the turn-1 `find_ast_pattern` `kind` value on the follow-redirects case (`regex` vs `array`/`string`). The harness logs `[variant-analyzer] prompt variant: variant-b` and the new `[tools] find_ast kind doc: <doc>` line, so each run records both dimensions.

## Success / kill bands

Diagnostic experiment; no "ship" outcome. Bands are about H6 (see the decision table). Every outcome is publishable — a null result ("worked examples don't move qwen-max's `kind` choice") is as informative as a positive one, because it tells us whether tool-schema descriptions are a useful lever on this model at all.

**Kill criterion (`docs/path-forward.md`):** unchanged. This experiment does not gate the 2026-10-26 kill date.

## Cost

$0 — DashScope free tier, qwen-max, 16 case-runs. ~5–15 min wall time.

## Risks

- **Day-to-day variance.** Mitigation: `baseline-C` is a same-session control; all comparisons within-session, never against the 2026-05-19 `variant-b` data.
- **The longer fix-C schema re-triggers mode A.** Possible — a longer tool schema lengthens the request. Mitigation: the H6 decision table explicitly watches for turn-1 give-ups returning; if they do, that is the reported result.
- **fix C shifts semver off its correct `kind: "template_string"`.** Mitigation: semver `kind` choice is tracked in both arms; a regression there is reported.

## Reproducibility (for the writeup)

The writeup records the commit SHA, both env-var values, and the bash loop above. Per-arm results land in `benchmarks/variants-calibration/results/2026-05-19-fixc-{baseline,worked-examples}-round{1..4}/`.

## See also

- `docs/research/2026-05-19-qwen-fix-a-isolation.md` — establishes `variant-b` as the working loop and the reproducible mode-C miss this experiment targets.
- `docs/research/2026-05-12-qwen-prompt-engineering.md` — the Bundle A+C run where fix C was first shipped but never reached.
- `docs/research/2026-05-11-variants-v2-model-portability.md` — the mode A/B/C failure-mode taxonomy.
- `docs/path-forward.md` — Track A sub-PR sequence and kill criteria.
- [PR #63](https://github.com/mythos-agent/mythos-agent/pull/63) — the fix-A isolation PR; this experiment is item 2 of its next-steps list and branches off it.
