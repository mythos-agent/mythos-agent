# Design — qwen-max fix-A isolation experiment

**Date:** 2026-05-19
**Issue trail:** [PR #62](https://github.com/mythos-agent/mythos-agent/pull/62) (Bundle A+C negative result), next-steps item 2; [issue #48](https://github.com/mythos-agent/mythos-agent/issues/48) Track A.
**Status:** approved, pre-implementation.

## TL;DR

The 2026-05-12 Bundle A+C experiment regressed qwen-max from 2/8 to 0/8. Fix A — a "## Workflow — REQUIRED" directive that was meant to *eliminate* the 1-turn give-up — instead universalized it (mode A went 2/8 → 8/8). The 2026-05-12 writeup raised two hypotheses for why and pre-registered an isolation experiment to tell them apart. This design implements that experiment: run qwen-max n=4 on three system-prompt arms — a no-directive `control`, a `variant-a` (numbered-list directive with the verbatim `variants: []` give-up token removed), and a `variant-b` (single imperative sentence, no list, no token) — against the same 2-case calibration corpus, and write up `docs/research/2026-05-19-qwen-fix-a-isolation.md`.

Goal: determine which feature of fix A's directive caused the regression — the verbatim negative-example token, or the numbered procedural list — or establish that neither prompt-only edit recovers tool use.

## Background — the two hypotheses

From `docs/research/2026-05-12-qwen-prompt-engineering.md`, the full fix-A directive that produced 0/8 was:

```
## Workflow — REQUIRED

1. Identify the root cause from the CVE (one sentence in `rootCauseAnalysis`).
2. Call `find_ast_pattern` (or `search_code` if the AST kind is unclear) AT LEAST ONCE to find candidate sites in the codebase.
3. Only after a tool call has returned, emit your final JSON answer.

An empty `variants` array is a valid answer — but only AFTER step 2. Emitting `variants: []` without calling any search tool is treated as a failed run, not a "no variants found" result. Identifying the root cause is step 1; mechanically searching for instances of it is step 2. Do NOT skip step 2.
```

All 8 case-runs ended in a 1-turn give-up with no tool call. Two hypotheses:

- **H-prime (negative-example prime):** the directive quotes the give-up output `variants: []` verbatim, twice, in an imperative give-up framing. For a disposition-prone model this acts as a one-shot demonstration of the give-up shape rather than a prohibition of it.
- **H-list (procedural list mis-execution):** the model reads the numbered "1 → 2 → 3" recipe as "do step 1, then step 3," treating step 2's prose as skippable scaffolding.

**Note on the baseline.** `main`'s `VARIANT_SYSTEM` already contains `{"rootCauseAnalysis": "...", "variants": []}` once, inside the "## Output Format" *schema example*. The give-up token is therefore not unique to fix A. What fix A added was that token in a *procedural give-up* context. `variant-a` removes only the procedural occurrences; the schema example stays (it is in `control` too). So `variant-a` isolates "the token in a give-up directive," not "the token anywhere."

## Hypothesis

**H5 (mechanism-isolation claim):** Exactly one of the two features of fix A's directive — the verbatim `variants: []` give-up token, or the numbered procedural list — is responsible for the 2026-05-12 regression, and removing it restores qwen-max tool use to at least the `control` rate.

Decision logic, read against the 2026-05-12 full-A result (0/8, list + token):

| Observation | Conclusion |
| --- | --- |
| `variant-a` recovers tool use, `variant-b` ≈ does too | H-prime: the verbatim token caused it |
| `variant-a` ≈ full-A (still gives up), `variant-b` recovers | H-list: the numbered list caused it |
| both recover | either edit alone is sufficient; the two features compound |
| neither recovers (both ≈ full-A) | H5 rejected — no prose-only directive variant salvages fix A; the next lever is SDK-level `tool_choice` forcing |
| `control` itself differs sharply from the 2026-05-11 2/8 | day-to-day variance is large; all arm comparisons must be read within-session only |

## Scope

### In scope

1. Refactor `VARIANT_SYSTEM` in `src/analysis/variant-analyzer.ts` into `buildVariantSystem(variant)` — a base prompt plus an optional workflow-directive section.
2. Add three prompt variants: `control` (no directive), `variant-a` (numbered list, no give-up token), `variant-b` (single sentence, no list, no token).
3. Select the active variant from the `MYTHOS_VARIANT_PROMPT` environment variable, read once in `variant-analyzer.ts`. Unset → `control`. Unrecognized value → throw a clear error.
4. Log the active variant once to stderr for reproducibility.
5. Unit-test variant resolution and the presence/absence of the directive features in each built prompt.
6. Run qwen-max n=4 on each of the three arms (24 case-runs total) against the GHSA-c2qf-rxjj-qqgw + GHSA-cxjh-pqwp-8mfp corpus.
7. Publish `docs/research/2026-05-19-qwen-fix-a-isolation.md`.

### Out of scope

- **Fix C.** This experiment branches off `main`, which has the baseline `find_ast_pattern` `kind` description (no worked examples). Fix C is therefore absent by construction — the 2026-05-12 writeup said to test C only after a working A. Not reverted, just never introduced on this branch.
- **The full-A arm (list + token).** Already measured at 0/8 on 2026-05-12. Re-running it is not free of value (same-session anchoring) but the existing data is the comparison point; a fourth arm is not worth the user's wall time given a strong prior.
- **A `--prompt-variant` CLI flag.** An env var is consistent with the existing `MYTHOS_BASE_URL` pattern and avoids plumbing a new option through `parseArgs → CliOptions → buildConfig → MythosConfig → VariantAnalyzer`.
- **The full 2×2 (quote × list).** Considered and rejected: the missing cell (sentence + token) is uninteresting, and the extra arms only pay off in the lower-probability "`variant-a` fails" branch. If that branch occurs, extend then.
- **qwen-plus, Sonnet 4.6.** One model, one axis.
- **Merging any prompt change to `main`.** This is a diagnostic experiment. The branch ships a writeup; whether any variant is later promoted is a separate decision.

## Concrete edits

All in `src/analysis/variant-analyzer.ts`. The directive, when present, is inserted between the "## Key Insight" paragraph and the "## Output Format" section — the same slot fix A used.

### `control`

`main`'s current `VARIANT_SYSTEM`, unchanged. No "## Workflow — REQUIRED" section.

### `variant-a` — numbered list, give-up token removed

Inserted directive:

```
## Workflow — REQUIRED

1. Identify the root cause from the CVE (one sentence in `rootCauseAnalysis`).
2. Call `find_ast_pattern` (or `search_code` if the AST kind is unclear) AT LEAST ONCE to find candidate sites in the codebase.
3. Only after a tool call has returned, emit your final JSON answer.

A result with no findings is valid — but only after step 2. Reporting no findings without first calling a search tool is treated as a failed run, not a genuine "no variants found" result. Identifying the root cause is step 1; mechanically searching for instances of it is step 2. Do NOT skip step 2.
```

Difference from full-A: the two occurrences of the literal `variants: []` are replaced with "a result with no findings" / "reporting no findings." The numbered list and every other word are identical to full-A.

### `variant-b` — single imperative sentence

Inserted directive:

```
## Workflow — REQUIRED

Before emitting your final JSON answer you MUST call `find_ast_pattern` or `search_code` at least once to search the codebase; a final answer produced without any preceding search-tool call is treated as a failed run.
```

No numbered list. No `variants: []` token.

**Known confound (documented, not eliminated):** `variant-b` removes both the list and the token, and is also the shortest prompt. If `variant-a` fails and `variant-b` recovers, the recovery is attributable to "list removed" only in combination with `variant-a`'s result (which holds the list constant while removing the token). A clean separation of "list" from "prompt length" would need the rejected 2×2; this design accepts the residual ambiguity as proportionate to a $0 follow-up.

## Implementation shape

- `type PromptVariant = "control" | "variant-a" | "variant-b"`.
- `buildVariantSystem(variant: PromptVariant): string` — composes the base text with the variant's directive (empty string for `control`).
- `resolvePromptVariant(raw: string | undefined): PromptVariant` — `undefined`/`""` → `"control"`; a recognized value → that value; anything else → `throw new Error(...)` naming the bad value and the valid set.
- `variant-analyzer.ts` reads `process.env.MYTHOS_VARIANT_PROMPT` once at module load, resolves it, builds the system prompt, and logs `[variant-analyzer] prompt variant: <name>` to stderr.
- Both `messages.create` call sites (`autoScan` and `searchForVariants`) use the single resolved system prompt.

## Experimental protocol

**Harness flags unchanged from 2026-05-12** except the new env var:

```bash
for v in control variant-a variant-b; do
  for i in 1 2 3 4; do
    MYTHOS_VARIANT_PROMPT=$v npm run benchmark:variants-calibration -- \
      --provider openai --model qwen-max \
      --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
      --results-subdir "2026-05-19-fixa-$v-round$i" \
      --log-turns
  done
done
```

- 3 arms × 4 rounds × 2 cases = 24 case-runs.
- Same cases (GHSA-c2qf-rxjj-qqgw + GHSA-cxjh-pqwp-8mfp), same fixture commits, MAX_TURNS=20, same parser.
- `DASHSCOPE_API_KEY` set by the user in their Git Bash window.

**Variable changed:** only `MYTHOS_VARIANT_PROMPT`.

**Attribution via turn logs:** the primary signal is `toolCalls` non-empty on turn 1 (tool use recovered) vs. `stopReason: end_turn` with `toolCalls: []` (mode A persists). Hit/miss is the secondary signal — recovery of tool use without a hit still distinguishes the hypotheses.

## Success / kill bands

This is a diagnostic experiment; there is no "ship" outcome. Bands are about which hypothesis the data supports (see the H5 decision table). Every outcome — including "neither variant recovers" — is publishable, because each one tells us a different thing about whether prompt-only work on qwen-max is worth continuing.

**Kill criterion (`docs/path-forward.md`):** unchanged. This experiment does not gate the 2026-10-26 kill date.

## Cost

$0 — DashScope free tier, qwen-max, 24 case-runs. ~15–25 min wall time (give-up runs ~3s, recovered runs ~35–70s).

## Risks

- **Day-to-day variance swamps the arm differences.** Mitigation: the `control` arm is the same-session baseline; all comparisons are read within-session, never against the cross-day 2026-05-11 2/8.
- **`variant-b`'s length confound.** Documented above; accepted as proportionate.
- **The env var is mistyped and silently runs `control`.** Mitigation: `resolvePromptVariant` throws on an unrecognized value; only unset falls through to `control`.

## Reproducibility (for the writeup)

The writeup will record the new commit SHA, the `MYTHOS_VARIANT_PROMPT` values, and the bash loop above. Per-arm results land in `benchmarks/variants-calibration/results/2026-05-19-fixa-{control,variant-a,variant-b}-round{1..4}/`.

## See also

- `docs/research/2026-05-12-qwen-prompt-engineering.md` — the Bundle A+C negative result this experiment follows up.
- `docs/research/2026-05-11-variants-v2-model-portability.md` — the qwen-max 2/8 baseline and failure-mode taxonomy.
- `docs/path-forward.md` — Track A sub-PR sequence and kill criteria.
- [PR #62](https://github.com/mythos-agent/mythos-agent/pull/62) — the Bundle A+C writeup PR; this experiment is item 2 of its next-steps list.
