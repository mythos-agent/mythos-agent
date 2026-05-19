# Variants v2 — qwen-max fix-A Isolation Experiment — 2026-05-19

> **TL;DR.** The 2026-05-12 Bundle A+C run regressed qwen-max from 2/8 to 0/8; fix A's "## Workflow — REQUIRED" directive universalized the 1-turn give-up it was meant to eliminate. That writeup raised two hypotheses — the directive's verbatim `variants: []` give-up token (H-prime) or its numbered procedural list (H-list) — and called H-prime "best-supported." This experiment ran three system-prompt arms n=4 on qwen-max to tell them apart: `control` (no directive), `variant-a` (the numbered list with the verbatim token removed), `variant-b` (a single imperative sentence, no list). The result is decisive and overturns the prior guess. **Turn-1 tool-call rate, the primary signal, is monotonic: variant-a 0/8 → control 4/8 → variant-b 8/8.** `variant-a` (list, token removed) behaves identically to 2026-05-12 full-A (list + token) — both give up on turn 1 in all 8 runs — so removing the token changed nothing: **H-prime is rejected.** `variant-b` (no list) recovered tool use completely, 8/8, and in fact *above* the no-directive control: **H-list is confirmed — the numbered procedural list is what suppressed tool use.** But recovering the loop did not recover accuracy: `variant-b` hit only 1/8, because once the 1-turn give-up is gone the misses fall back to the 2026-05-11 failure modes B (over-escaped predicates) and C (wrong AST `kind`). Total cost: **\$0** (DashScope free tier).

## Why this writeup exists

`docs/research/2026-05-12-qwen-prompt-engineering.md` documented the Bundle A+C regression: every one of 8 qwen-max case-runs ended in a 1-turn give-up (`stopReason: end_turn`, `toolCalls: []`, `variants: []`). It pre-registered an isolation experiment — quoted here from its next-steps item 2:

> Run n=4 each on two A-variants: (a) the directive with the verbatim `variants: []` quotes removed; (b) the directive collapsed to a single imperative sentence with no numbered list. If (a) recovers and (b) does not, the negative-prime hypothesis holds; if (b) recovers, the procedural-list hypothesis holds.

This experiment is that item, plus a same-session `control` arm — the design (`docs/superpowers/specs/2026-05-19-qwen-fix-a-isolation-design.md`) added it because the comparison is otherwise cross-day, and the 2026-05-11 qwen-max baseline (2/8) is six days stale.

The 2026-05-12 writeup explicitly hedged its mechanism guess — "n=8 on one prompt variant cannot prove a mechanism … We cannot isolate which sub-feature of edit A is responsible." This experiment resolves that, and the answer is not the one that writeup leaned toward.

## Hypothesis

**H5 (mechanism-isolation claim):** exactly one feature of fix A's directive — the verbatim `variants: []` give-up token, or the numbered procedural list — caused the 2026-05-12 regression, and removing it restores qwen-max tool use.

Decision table, pre-registered in the design, read against the 2026-05-12 full-A result (0/8, list + token):

| Observation | Conclusion |
| --- | --- |
| `variant-a` recovers tool use, `variant-b` ≈ does too | H-prime: the verbatim token caused it |
| `variant-a` ≈ full-A (still gives up), `variant-b` recovers | H-list: the numbered list caused it |
| both recover | either edit alone is sufficient |
| neither recovers | H5 rejected — no prose-only variant salvages fix A |
| `control` differs sharply from the 2026-05-11 2/8 | day-to-day variance is large; read arms within-session only |

**Result: the H-list row fires, and so does the day-variance row.**

## Methodology

**Unchanged from the 2026-05-12 protocol:**

- Harness: `npm run benchmark:variants-calibration -- --log-turns`
- Model: `qwen-max` via `--provider openai --base-url https://dashscope.aliyuncs.com/compatible-mode/v1`
- Cases: GHSA-c2qf-rxjj-qqgw (semver ReDoS) and GHSA-cxjh-pqwp-8mfp (follow-redirects), fixture commits `2f738e9` and `8526b4a`, MAX_TURNS=20, same parser
- n=4 per arm, one `--results-subdir` per round

**Changed — the experiment variable:** the system prompt is selected at module load from the `MYTHOS_VARIANT_PROMPT` environment variable (`control` | `variant-a` | `variant-b`), implemented in `src/analysis/variant-prompt.ts` and wired into `variant-analyzer.ts` (branch `qwen-fix-a-isolation`, commit `e490d3a`). The three arms:

- **`control`** — the original `VARIANT_SYSTEM`, no "## Workflow — REQUIRED" section.
- **`variant-a`** — the full 2026-05-12 fix-A numbered 3-step list, with the two verbatim `variants: []` give-up tokens replaced by neutral phrasing ("a result with no findings"). Isolates the token: list held constant, token removed.
- **`variant-b`** — a single imperative sentence ("Before emitting your final JSON answer you MUST call `find_ast_pattern` or `search_code` at least once …"), no numbered list, no token.

**Confirmation the prompts were live and distinct.** Turn-1 `inputTokens` were stable within each arm and separated between them: `control` 1721/1694 (semver/follow-redirects), `variant-a` 1865/1838 (+144, the numbered-list directive), `variant-b` 1771/1744 (+50, the single sentence). The harness also logged `[variant-analyzer] prompt variant: <arm>` on every run, matching the `--results-subdir`.

**Primary signal:** turn-1 tool-call rate — did the model call `find_ast_pattern`/`search_code` on turn 1, or give up. Hit/miss is secondary; the regression under study is a *loop-entry* failure, and a recovered loop that still misses is a different (and informative) outcome from a loop that never starts.

## Runs

24 case-runs (3 arms × 4 rounds × 2 cases). "tool" = turn-1 `stopReason: tool_use`; "give-up" = turn-1 `end_turn` with `toolCalls: []`.

### control (no directive)

| Round | semver | follow-redirects |
| --- | --- | --- |
| 1 | tool (`kind=template_string`) → 0 variants | give-up |
| 2 | give-up | tool (`kind=regex`) → 0 variants |
| 3 | give-up | tool (`kind=regex`) → 0 variants |
| 4 | give-up | tool (`kind=regex`) → 0 variants |

Turn-1 tool calls: **4/8** (semver 0/4, follow-redirects 4/4). Hits: **0/8**.

### variant-a (numbered list, token removed)

| Round | semver | follow-redirects |
| --- | --- | --- |
| 1–4 | give-up (all 4) | give-up (all 4) |

Turn-1 tool calls: **0/8**. Hits: **0/8**. Every run is a 1-turn give-up — bit-for-bit the same disposition as 2026-05-12 full-A.

### variant-b (single sentence, no list)

| Round | semver | follow-redirects |
| --- | --- | --- |
| 1 | tool (`kind=template_string`) → 0 variants | tool (`kind=regex`) → 0 variants |
| 2 | tool (`kind=template_string`) → 0 variants | tool (`kind=regex`) → 0 variants |
| 3 | tool (`kind=template_string`) → 0 variants | tool (`kind=regex`) → 0 variants |
| 4 | **tool (`kind=template_string`) → 11 variants, 5 in band — MATCH** | tool (`kind=regex`) → 0 variants |

Turn-1 tool calls: **8/8**. Hits: **1/8**.

### Aggregate

| Arm | Turn-1 tool-call rate | Hits |
| --- | --- | --- |
| `variant-a` (list + no token) | 0/8 | 0/8 |
| `control` (no directive) | 4/8 | 0/8 |
| `variant-b` (no list) | 8/8 | 1/8 |
| *(2026-05-12 full-A: list + token)* | *0/8* | *0/8* |

## Attribution

**H-prime is rejected.** `variant-a` is fix A's numbered list with the verbatim `variants: []` token removed. It gave up on turn 1 in all 8 runs — identical to 2026-05-12 full-A (list **+** token), which also gave up 8/8. Removing the token moved the tool-call rate by exactly zero. The verbatim give-up token, which the 2026-05-12 writeup called the "best-supported" culprit, is not the cause.

**H-list is confirmed.** `variant-b` carries the same imperative intent as fix A ("you MUST call a search tool before answering", "treated as a failed run") but expresses it as one sentence instead of a numbered "1 → 2 → 3" list. It called a tool on turn 1 in all 8 runs. The numbered procedural list is what suppressed tool use. The 2026-05-12 writeup's secondary hypothesis — that qwen-max reads the numbered recipe as "do step 1, then step 3," treating the step-2 tool call as skippable scaffolding — is the surviving explanation.

**The directive's intent is sound; only its numbered-list encoding is toxic.** `variant-b` (8/8 tool calls) beats `control` (4/8) — the single-sentence directive lifts tool use *above* having no directive at all. So "tell qwen-max to call a tool before answering" works as an instruction. Encode that same instruction as a numbered list and it does the opposite, driving tool use to 0/8 — below baseline.

**Recovering the loop did not recover accuracy.** `variant-b` called a tool 8/8 but hit only 1/8. The misses are no longer mode A (give-up); they are the other two 2026-05-11 failure modes, now visible because mode A no longer masks them:

- **follow-redirects, 4/4 `kind=regex`** — mode C. The fix lives in an array literal of header strings, not a regex AST node; `kind=regex` returns 0 matches every time, exactly as on 2026-05-11.
- **semver, 4/4 `kind=template_string` (correct kind) but 1/4 hit** — mode B. The three misses used over-escaped or compound `text_predicates` (e.g. `["\\\\s[*+]","\\${"]`, where the doubled backslash matches a literal backslash and the second predicate filters out every real match). The one hit, `variant-b` round 4 semver, used a single clean predicate `\\s[+*]` with the correct kind and produced 11 variants, 5 in the calibration band — the same shape as the 2026-05-11 successful runs.

**The same-session control earned its place.** `control` hit 0/8 this session; the 2026-05-11 qwen-max baseline on the equivalent prompt hit 2/8. Same harness, same cases, same fixtures, same model — only the date differs. Day-to-day variance on this 2-case corpus is large enough to swamp a 2/8 difference, so every comparison in this writeup is read within-session, never against 2026-05-11. Without the control arm the `variant-b` 1/8 could have been misread as a regression from 2/8; against the within-session `control` 0/8 it is, correctly, noise.

## What this proves about the kill criterion

Quoted verbatim from `docs/path-forward.md`:

> **Kill criteria:** if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough. At that point, the next bet is Track C (differential fuzzing), not deeper Track A iteration.

`variant-b` made a serious attempt at the AST matcher in all 8 runs and produced a clean MATCH once (11 variants, 5 in band). The 2026-04-27 Sonnet 4.6 run already cleared the criterion. **This experiment does not trigger the kill criterion**, and the 2026-10-26 kill date is unchanged. What it changes is the diagnosis: qwen-max's mode-A loop-entry failure is now understood and prose-fixable (drop the numbered list), but fixing it only exposes modes B and C — so prompt-only work on qwen-max does not, on this evidence, move the hit rate.

## What this writeup deliberately does not claim

- **"`variant-b` is a fix to ship."** It is not. It removes mode A, but it hit 1/8 — within noise of the `control` 0/8. It restores the agent loop; it does not make qwen-max good at variant analysis. Promoting it would trade a loud failure (give-up) for a quiet one (tool call → 0 variants).
- **"The numbered list breaks every model."** Only qwen-max was tested. Sonnet 4.6 runs a deep multi-turn loop and was never observed to give up; the numbered list may be inert or even helpful there. Untested.
- **"qwen-max cannot do variant analysis."** It can when AST `kind` and `text_predicates` align — `variant-b` round 4 produced 11 variants with 5 in band. The ceiling is reliability of the tool call, not capability.
- **"H-list is the complete mechanism."** The experiment shows the numbered list is *sufficient* to suppress tool use and its removal is *sufficient* to restore it. Whether qwen-max literally "jumps 1→3" or the list interacts with something else in the prompt is an interpretation consistent with the data, not a proven internal trace.
- **"The 1/8 vs 0/8 difference is real signal."** It is not claimed as such. At n=8 per arm, 1 hit versus 0 is not distinguishable. The hit-rate finding of this experiment is "no arm recovered hits," not "`variant-b` is marginally better."
- **mythos-agent has found a 0-day.** Unchanged from every prior writeup: all calibration cases are known CVEs on known vulnerable commits.

## Cost

| Item | Runs | Provider | API cost |
| --- | --- | --- | --- |
| qwen-max, 3 arms × n=4 | 24 case-runs | DashScope (free tier) | \$0 |

**Total today: \$0.** Wall time ≈ 3 min across all 24 case-runs (give-up runs ~2–6 s; the one MATCH took 55 s).

Research-arc cost to date: ~\$23 of Anthropic API credit (2026-04-26 + 2026-04-27, Sonnet) + \$0 across all three Qwen writeups (2026-05-11, 2026-05-12, today) = ~\$23 across five writeups.

## Reproducibility

```bash
git clone https://github.com/mythos-agent/mythos-agent
cd mythos-agent
git checkout e490d3a   # branch qwen-fix-a-isolation: MYTHOS_VARIANT_PROMPT support
npm install

export DASHSCOPE_API_KEY="sk-..."

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

For Alibaba Cloud International accounts, replace the base URL with `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`.

Per-arm results land in `benchmarks/variants-calibration/results/2026-05-19-fixa-{control,variant-a,variant-b}-round{1..4}/`. Each directory has `summary.json`, two `<GHSA>.json` files, and two `<GHSA>.turns.jsonl` diagnostic logs.

**Branch / SHA:** `qwen-fix-a-isolation` at `e490d3a`.

**Expected variance:** the agent loop is non-deterministic, but the per-arm signal here was unusually clean — `variant-a` 8/8 give-ups, `variant-b` 8/8 tool calls. The headline (numbered list → 0/8 tool calls; single sentence → 8/8) is what to expect on reproduction; the hit rate, bounded by day-variance and modes B/C, is not.

## Next steps

In priority order:

1. **Never encode a qwen-max directive as a numbered list.** If a workflow directive is wanted for qwen-max at all, use `variant-b`'s single-sentence prose form. But note this only removes mode A; it does not lift the hit rate, so there is no reason to ship it on its own.
2. **Test fix C on top of a working loop.** Fix C (the worked-example AST-`kind` schema from Bundle A+C / PR #62) was untestable in the 2026-05-12 run because mode A masked it, and untestable here for the same reason in `control`/`variant-a`. `variant-b` now provides a loop that reliably reaches the `find_ast_pattern` call — the follow-redirects `kind=regex` mode-C miss is now reproducible 4/4 and is the clean target. Layer fix C onto `variant-b`'s prose directive and re-run n=4.
3. **Sonnet 4.6 n=4 reliability runs (~\$10–15).** Still the cheapest hard data point against the 2026-10-26 kill date, and still unaddressed — carried forward from the 2026-05-11 and 2026-05-12 next-steps lists.

## See also

- `docs/research/2026-05-12-qwen-prompt-engineering.md` — the Bundle A+C regression this experiment diagnoses; its lead hypothesis (H-prime) is rejected here.
- `docs/research/2026-05-11-variants-v2-model-portability.md` — the qwen-max failure-mode taxonomy (modes A/B/C) this writeup refers back to.
- `docs/superpowers/specs/2026-05-19-qwen-fix-a-isolation-design.md` — the pre-registered design, including the H5 decision table.
- `docs/path-forward.md` — Track A sub-PR sequence and kill criteria.
- [PR #62](https://github.com/mythos-agent/mythos-agent/pull/62) — the Bundle A+C writeup PR; this experiment is item 2 of its next-steps list.
