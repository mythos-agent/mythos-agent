# Variants v2 — fix C on variant-b's Working Loop — 2026-05-19

> **TL;DR.** The 2026-05-19 fix-A isolation experiment left qwen-max with a working agent loop (the `variant-b` prompt arm, 8/8 turn-1 tool calls) but a reproducible follow-redirects miss: the model calls `find_ast_pattern` with `kind: "regex"` when the fix actually lives in an array literal of header strings (failure mode C). Fix C — the worked-example AST-`kind` schema description pre-registered in [PR #62](https://github.com/mythos-agent/mythos-agent/pull/62)'s Bundle A+C, never testable until now because mode A masked it — has a bullet aimed at exactly this case: *"Header allowlist/denylist as inline strings → kind: array or string (NOT regex…)"*. This experiment ran qwen-max n=4 on two arms, prompt held at `variant-b`, toggling `MYTHOS_FIND_AST_KIND_DOC` between `baseline` and `worked-examples`. **Result: a clean null. fix C did not move the `kind` choice — follow-redirects was `kind: "regex"` in all 8 runs of both arms.** H6 is rejected: a tool-schema `description` field is too weak a lever to change qwen-max's `kind` reasoning. Guards held — no mode-A regression (16/16 runs reached the tool call), and semver stayed on its correct `kind: "template_string"` in both arms. Total cost: **\$0** (DashScope free tier).

## Why this writeup exists

`docs/research/2026-05-19-qwen-fix-a-isolation.md` established that the `variant-b` prompt arm gives qwen-max a working agent loop — it calls a search tool on turn 1 in 8/8 runs — but follow-redirects still missed 4/4 via mode C: `kind: "regex"` on a fix that lives in a JavaScript array literal, returning 0 matches every time. That writeup's next-steps item 2:

> **Test fix C on top of a working loop.** Fix C … was untestable in the 2026-05-12 run because mode A masked it … `variant-b` now provides a loop that reliably reaches the `find_ast_pattern` call — the follow-redirects `kind=regex` mode-C miss is now reproducible 4/4 and is the clean target. Layer fix C onto `variant-b`'s prose directive and re-run n=4.

This experiment is that item. Fix C was first shipped in the 2026-05-12 Bundle A+C but never reached a decision point — the bundled fix A killed the loop before any tool call. This is its first real test, on the loop `variant-b` provides.

A pre-plan code investigation confirmed the experiment's premise is mechanically sound: the AST matcher (`src/analysis/ast-matcher/matcher.ts:113-127`) matches `kind` by a direct `Set.has(node.type)` check against tree-sitter node types — no allow-list — and `"array"` / `"string"` are valid `tree-sitter-javascript` node types. If qwen-max had passed `kind: "array"`, the matcher would have found the header-allowlist array. It never did.

## Hypothesis

**H6 (fix-C claim):** On qwen-max running the `variant-b` prompt, the fix-C worked-example `kind` schema moves the follow-redirects `find_ast_pattern` call off `kind: "regex"` toward `kind: "array"`/`"string"`, relative to the same-session `baseline` arm.

Decision table, pre-registered in the design, read within-session:

| Observation | Conclusion |
| --- | --- |
| fix-C picks non-`regex` kind on follow-redirects in a majority of runs | H6 supported — the worked-example list shifts qwen-max's `kind` choice |
| fix-C still picks `kind: "regex"` ≈ 4/4 | H6 rejected — the worked-example list does not change the choice; a schema description is the wrong lever |
| fix-C re-introduces mode A, or regresses semver's correct `kind: "template_string"` | fix C has a harmful side effect |

**Result: the H6-rejected row fires. The side-effect row does not.**

## Methodology

**Unchanged from the 2026-05-19 fix-A protocol:**

- Harness: `npm run benchmark:variants-calibration -- --log-turns`
- Model: `qwen-max` via `--provider openai --base-url https://dashscope.aliyuncs.com/compatible-mode/v1`
- Cases: GHSA-c2qf-rxjj-qqgw (semver ReDoS) and GHSA-cxjh-pqwp-8mfp (follow-redirects), fixture commits `2f738e9` and `8526b4a`, MAX_TURNS=20, same parser
- n=4 per arm, one `--results-subdir` per round

**Held constant:** `MYTHOS_VARIANT_PROMPT=variant-b` on every run — the established working loop.

**The experiment variable:** `MYTHOS_FIND_AST_KIND_DOC`, a new env var (commit `e60a111`) selecting the `find_ast_pattern` `kind` schema `description`:

- **`baseline`** — the original terse description (`'tree-sitter node kind to match (e.g. "call_expression", …). May be a single string or an array …'`).
- **`worked-examples`** — fix C, verbatim from PR #62 commit `313661c`: a lead sentence ("Pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class") followed by five worked-example bullets, one of which is *"Header allowlist/denylist as inline strings → kind: "array" or "string" (NOT "regex" — the headers are array elements, not a regex literal)"*.

**Confirmation the schemas were live and distinct.** Turn-1 `inputTokens` were stable within each arm and separated between them: `baseline` 1771/1744 (semver/follow-redirects), `worked-examples` 1872/1845 — a uniform +101 tokens, the cost of the longer fix-C description. The harness logged `[tools] find_ast kind doc: <arm>` and `[variant-analyzer] prompt variant: variant-b` on every run. The model received the worked examples; it did not act on them.

**Primary signal:** the turn-1 `find_ast_pattern` `kind` value on the follow-redirects case — `regex` vs `array`/`string`.

## Runs

16 case-runs (2 arms × 4 rounds × 2 cases). Every run reached turn 2, i.e. turn 1 was a tool call — mode A did not occur anywhere.

### baseline (terse kind description)

| Round | semver — turn-1 `kind` → outcome | follow-redirects — turn-1 `kind` → outcome |
| --- | --- | --- |
| 1 | `template_string` → 9 variants, **MATCH** | `regex` → 0 variants, miss |
| 2 | `template_string` → 7 variants, **MATCH** | `regex` → 0 variants, miss |
| 3 | `template_string` → 0 variants, miss | `regex` → 0 variants, miss |
| 4 | `template_string` → 0 variants, miss | `regex` → 0 variants, miss |

follow-redirects `kind`: **4/4 `regex`**. Hits: **2/8**.

### worked-examples (fix-C kind description)

| Round | semver — turn-1 `kind` → outcome | follow-redirects — turn-1 `kind` → outcome |
| --- | --- | --- |
| 1 | `template_string` → 9 variants, **MATCH** | `regex` → 0 variants, miss |
| 2 | `template_string` → 0 variants, miss | `regex` → 0 variants, miss |
| 3 | `template_string` → 0 variants, miss | `regex` → 0 variants, miss |
| 4 | `template_string` → 0 variants, miss | `regex` → 0 variants, miss |

follow-redirects `kind`: **4/4 `regex`**. Hits: **1/8**.

### Aggregate

| Arm | follow-redirects `kind` | semver `kind` | Turn-1 tool-call rate | Hits |
| --- | --- | --- | --- | --- |
| `baseline` | 4/4 `regex` | 4/4 `template_string` | 8/8 | 2/8 |
| `worked-examples` (fix C) | 4/4 `regex` | 4/4 `template_string` | 8/8 | 1/8 |

## Attribution

**H6 is rejected.** Fix C's worked-example list — including a bullet that nearly verbatim describes the follow-redirects case (`Header allowlist/denylist as inline strings → … NOT "regex"`) — did not change qwen-max's `kind` choice on that case in a single one of 8 runs. baseline picked `regex` 4/4; worked-examples picked `regex` 4/4. The model never proposed `kind: "array"` or `kind: "string"`. A tool-schema parameter `description` is too weak a lever to redirect qwen-max's argument reasoning.

**The mechanism the lead sentence names is the mechanism that beat it.** Fix C's first sentence — "Pick the kind that holds the LITERAL TEXT being changed in the fix, not the kind that describes the bug class" — diagnoses the error precisely: qwen-max reasons from the bug *class* (the follow-redirects flaw is regex-/allowlist-shaped) to `kind: "regex"`, when the *fix* edits an array literal. Fix C states the correction in plain language and gives the matching worked example. qwen-max read it (the +101-token schema was in every request) and picked `regex` anyway. Naming the error inside the tool description does not stop the model committing it.

**The guards held — fix C is inert, not harmful.**

- **No mode-A regression.** All 16 runs reached turn 2; the longer worked-examples schema did not push qwen-max back into the 1-turn give-up. `variant-b`'s loop is robust to the extra schema text.
- **No semver regression.** Both arms picked `kind: "template_string"` on all 8 semver runs — the correct kind. Fix C did not corrupt the case that was already working.

**Hit rate carries no signal.** baseline 2/8, worked-examples 1/8 — both within noise of each other and of the 2026-05-19 `variant-b` 1/8. The semver hits/misses vary round to round with the `text_predicates` the model writes (mode B — e.g. `worked-examples` round 2 semver picked the correct `kind: "template_string"` but a predicate `["\\\\s\\*|\\\\s\\+","\\${"]` whose doubled backslash matches a literal backslash, yielding 0 variants). Fix C touches `kind`, not predicates, so it neither could nor did move the hit rate. follow-redirects was 0/8 in both arms — unchanged, because the `kind` it depends on never changed.

## What this proves about the kill criterion

Quoted verbatim from `docs/path-forward.md`:

> **Kill criteria:** if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough. At that point, the next bet is Track C (differential fuzzing), not deeper Track A iteration.

Both arms made serious attempts at the AST matcher in all 16 runs, and `baseline` produced two clean semver MATCHes (9 and 7 variants). The 2026-04-27 Sonnet 4.6 run already cleared the criterion. **This experiment does not trigger the kill criterion**, and the 2026-10-26 kill date is unchanged. What it sharpens: the follow-redirects mode-C miss on qwen-max is not closable by a tool-schema description edit, and the cheap prompt/schema levers for qwen-max are now exhausted.

## What this writeup deliberately does not claim

- **"Fix C is a bad edit."** Fix C is well-targeted prose — its lead sentence correctly diagnoses the error and its bullet correctly prescribes the fix. The finding is narrower: a tool-schema `description` is the wrong *delivery channel* for that guidance on qwen-max. The same words might work in a different position, or on a different model.
- **"qwen-max ignores tool schemas entirely."** It does not — it reads `find_ast_pattern`'s schema well enough to call the tool with a structurally valid `kind`, `text_predicates`, and `file_glob` every time. It under-applies the *advisory* prose in the `description`, not the schema's structure.
- **"The follow-redirects case is unsolvable."** It is unsolved by this lever. A constrained `kind` enum, a `search_code` fallback, or surfacing candidate kinds from the root cause are untested alternatives. This experiment closes one option, not the problem.
- **"worked-examples is worse (1/8 vs 2/8)."** Not claimed — at n=8 the difference is noise, and the hit rate is governed by mode-B predicate variance that fix C does not touch.
- **mythos-agent has found a 0-day.** Unchanged from every prior writeup: all calibration cases are known CVEs on known vulnerable commits.

## Cost

| Item | Runs | Provider | API cost |
| --- | --- | --- | --- |
| qwen-max, 2 arms × n=4 | 16 case-runs | DashScope (free tier) | \$0 |

**Total today: \$0.** Wall time ≈ 3.5 min across all 16 case-runs.

Research-arc cost to date: ~\$23 of Anthropic API credit (2026-04-26 + 2026-04-27, Sonnet) + \$0 across all four Qwen writeups (2026-05-11, 2026-05-12, 2026-05-19 fix-A, today) = ~\$23 across six writeups.

## Reproducibility

```bash
git clone https://github.com/mythos-agent/mythos-agent
cd mythos-agent
git checkout e60a111   # branch qwen-fix-c-on-variant-b: MYTHOS_FIND_AST_KIND_DOC support
npm install

export DASHSCOPE_API_KEY="sk-..."

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

For Alibaba Cloud International accounts, replace the base URL with `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`.

Per-arm results land in `benchmarks/variants-calibration/results/2026-05-19-fixc-{baseline,worked-examples}-round{1..4}/`.

**Branch / SHA:** `qwen-fix-c-on-variant-b` at `e60a111`.

**Expected variance:** the agent loop is non-deterministic, but the primary signal here was unusually clean — `kind: "regex"` on follow-redirects in 8/8 runs across both arms. The headline (fix C does not move the `kind` choice) is what to expect on reproduction.

## Next steps

In priority order:

1. **Stop iterating prompt/schema text on qwen-max.** Three experiments now converge: qwen-max responds to blunt *structural* prompt changes (2026-05-19: removing the numbered list restored tool use 0/8 → 8/8) but not to *instructional prose content* — not a system-prompt negative example (2026-05-12), and not a tool-schema worked example (today). The cheap qwen-max levers are spent; further prompt engineering on this model has poor expected return.
2. **Sonnet 4.6 n=4 reliability runs (~\$10–15).** Now unambiguously the priority. It has been carried on every next-steps list since 2026-05-11, and the qwen-max prompt-engineering thread — the reason it kept being deferred — has reached its natural end. Sonnet is the only model with a stable per-round hit pattern; n=4 is the cheapest hard data point against the 2026-10-26 kill date.
3. **If qwen-max's follow-redirects case is revisited later, change the channel, not the words.** A constrained `kind` enum in the schema, or having the agent emit candidate kinds from the root cause rather than free-choosing, are untested levers that do not rely on advisory prose. Lower priority than the Sonnet runs.

## See also

- `docs/research/2026-05-19-qwen-fix-a-isolation.md` — establishes `variant-b` as the working loop and the reproducible mode-C miss this experiment targets.
- `docs/research/2026-05-12-qwen-prompt-engineering.md` — the Bundle A+C run where fix C was first shipped but never reached a decision point.
- `docs/research/2026-05-11-variants-v2-model-portability.md` — the mode A/B/C failure-mode taxonomy.
- `docs/superpowers/specs/2026-05-19-qwen-fix-c-on-variant-b-design.md` — the pre-registered design and H6 decision table.
- `docs/path-forward.md` — Track A sub-PR sequence and kill criteria.
- [PR #63](https://github.com/mythos-agent/mythos-agent/pull/63) — the fix-A isolation PR; this experiment is item 2 of its next-steps list and branches off it.
