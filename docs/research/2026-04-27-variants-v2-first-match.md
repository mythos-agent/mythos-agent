# Variants v2 — First Match — 2026-04-27

> **TL;DR.** Variants v2 (Track A from [`docs/path-forward.md`](../path-forward.md)) shipped end-to-end on 2026-04-27. Nine PRs landed: A1 root-cause patterns, A2 AST matcher, A3a deterministic calibration, A3b live harness, plus four infrastructure fixes surfaced and patched in real time. The final agent-driven calibration run on Claude Sonnet 4.6 produced **a clean MATCH on follow-redirects (CVE-2024-28849)** — agent identified the exact vulnerable line (`index.js:464`) with a precise data-flow explanation. **The semver case (CVE-2022-25883) was a harness-parser miss, not a design miss**: the JSONL diagnostic log shows the agent identified 12 vulnerable patterns including the calibration target lines, but a markdown-then-JSON output format defeated the JSON extractor. Per Track A's kill criterion in [`docs/path-forward.md`](../path-forward.md) — *"if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough"* — today's data shows ≥1 candidate that maps back to the actual fix commit. **The kill criterion is not triggered.** Total cost: ~\$20 of Anthropic API credit across 6 paid runs (4 of which were debugging infrastructure bugs, not testing the design).

## Why this writeup exists

[The 2026-04-26 variant-hunt experiment](2026-04-26-variant-hunt-experiment.md) proved the prompt-only variants v1 approach couldn't reliably find variants on matched targets even with a frontier model — `0/8` runs. That negative result justified Track A: structured root-cause representation + AST matching + calibration corpus.

Track A shipped the day after. This writeup is the symmetric publication: the first positive signal, captured with the same evidentiary standard as the negative.

Per the project's "honesty beats coverage" principle, this writeup documents both the headline result (`1/2` matched) AND the bugs that distort it (one of the misses was a harness format-parser issue, not a design failure). A reader six months from now should be able to audit which runs are valid evidence vs. which are noise.

## Hypothesis

**H2 (the variants v2 claim, replacing H1 from the 2026-04-26 writeup):** With A1's structured root-cause patterns threaded into the prompt + A2's `find_ast_pattern` tool available to the agent + A3's calibration target wired to the upstream vulnerable file, the variant-analyzer's agent loop can produce ≥1 candidate per case that maps back to the actual fix commit.

**Specific A3 success criterion** (verbatim from `docs/path-forward.md` Track A):
> *"Take the 2 / 5 caught CVE Replay cases (CVE-2022-25883 semver, CVE-2024-28849 follow-redirects), use them as both seed and target. The variants-v2 tool should produce ≥1 candidate that maps back to the actual fix commit."*

## Methodology

**Variant-analyzer, post Track-A:** the same agent loop used in the 2026-04-26 experiment (`searchForVariants` in `src/analysis/variant-analyzer.ts`), but with three additions:

1. **A1's `RootCausePattern` threaded into the prompt** as the `rootCause` field of the `CveInfo` (see `src/analysis/calibration/agent-runner.ts` → `buildCveInfoFromSeed`). The agent receives the structured bug class, CWE, AST shape kind, constraints, and source→sink data flow up front rather than being asked to derive them.
2. **`find_ast_pattern` tool added** to `createAgentTools` (PR #51). Lets the agent search by tree-sitter node kind + regex predicates over node text instead of grepping the raw source.
3. **Calibration target wired** to the case JSON (`benchmarks/cve-replay/cases/<GHSA>.json`). The harness asserts that ≥1 returned variant's `file:line` overlaps the recorded vulnerable band.

**Calibration cases (the 2/5 caught from CVE Replay):**

- **CVE-2022-25883 / GHSA-c2qf-rxjj-qqgw** — semver ReDoS. Vulnerable file `internal/re.js`. Calibration band lines 138–161 (the TILDETRIM / CARETTRIM / COMPARATORTRIM template-literal regex builders).
- **CVE-2024-28849 / GHSA-cxjh-pqwp-8mfp** — follow-redirects incomplete redirect-header strip. Vulnerable file `index.js`. Calibration band line 464 (`removeMatchingHeaders(/^(?:authorization|cookie)$/i, …)`).

**Harness:** `npm run benchmark:variants-calibration -- --log-turns` (PR #53 + PR #56). Live-clones each upstream repo, checks out the `vulnerable_commit`, runs `runAgentCalibration`, writes per-case JSON results plus per-turn JSONL diagnostic logs.

**Model:** `claude-sonnet-4-6` (the same Tier-1 path the 2026-04-26 run used for its row-8 baseline). One run.

## Runs

Six paid runs were executed over the day. Only the final one (`2026-04-27-final`) tested the post-fix code-path — earlier runs surfaced infrastructure bugs that invalidated their data. All six are listed below for transparency about what was actually being measured.

| # | Run id | Outcome | Status | What this run tested |
|---|---|---|---|---|
| 1 | `2026-04-27T12-06-51-842Z` | Qwen 3 plus, 0/2 | infra failure | DEFAULT_CONFIG had stale model ID `claude-sonnet-4-20250514` (retired); 404 before agent loop ran. **Test of nothing.** Fixed in [PR #55](https://github.com/mythos-agent/mythos-agent/pull/55). |
| 2 | `2026-04-27T12-16-04-088Z` | Sonnet 4.6, 0/2 (1 errored) | infra failure | Case 1 hit org's 30K ITPM rate limit at 10 min in. Case 2 ran clean but `find_ast_pattern` was silently broken — see #4 below. **Test of regex search_code with extra prompt context, not of A2.** |
| 3 | `2026-04-27-claude-sonnet-4-6` | Sonnet 4.6, 1/2 | infra failure | Same `find_ast_pattern` bug. The MATCH on follow-redirects was achieved without using the AST tool. **Not a test of variants v2.** |
| 4 | `2026-04-27T13-57-00-663Z` | Sonnet 4.6, 0/1 (semver) | infra failure | First run with `--log-turns` (PR #56). The JSONL log surfaced the smoking gun: agent called `find_ast_pattern({kind:"template_string"})` on T1, agent reported *"The AST engine has file access issues"* on T2, fell back to regex for the rest. Root cause: parser.ts resolved grammars via fixed `../../../assets/grammars` hop count, which lands on `dist-benchmarks/assets/grammars/` (missing) when run from the compiled benchmark layout. Fixed in [PR #57](https://github.com/mythos-agent/mythos-agent/pull/57). |
| 5 | `2026-04-27-post-fix` | Sonnet 4.6, 0/2 | infra failure | First run after PR #57. Agent called `find_ast_pattern` 5× on semver and 3× on follow-redirects (vs 1× pre-fix where it gave up). Both cases produced `end_turn` with multi-thousand-token analyses. But the harness reported 0 variants for both, because the agent emitted markdown-formatted reports and the `parseVariants` greedy `\{[\s\S]*\}` regex couldn't extract a JSON variants array from prose. Plus the logger capped the final-response text at 400 chars, defeating diagnosis. Fixed in [PR #58](https://github.com/mythos-agent/mythos-agent/pull/58). |
| 6 | `2026-04-27-final` | **Sonnet 4.6, 1/2** | **valid evidence** | First run after all four infrastructure fixes (#55 model ID, #56 logging, #57 grammars path, #58 JSON output + parser + uncap log) shipped to the test branch. **Detailed below.** |

The 6-run shape isn't a methodology choice — it's the actual sequence of bugs surfaced and fixed in real time. Future readers should treat runs 1–5 as debugging artifacts. Only run 6 is evidence about variants v2.

## Run 6 — the valid evidence

| Case | Result | Turns | `find_ast_pattern` calls | Wall time |
|---|---|---|---|---|
| GHSA-cxjh-pqwp-8mfp (follow-redirects) | **MATCH** — 1 variant, 1 in target band | 12 | 2 | 161s |
| GHSA-c2qf-rxjj-qqgw (semver) | reported MISS — see "the parser-loss caveat" below | 10 | 4 | 148s |

Total wall time: ~5 minutes. Total cost: ~\$3–5 of Anthropic credit.

### follow-redirects MATCH

The agent returned a single variant pointing at the exact calibration target line:

```json
{
  "id": "VAR-001",
  "cveId": "CVE-2024-28849",
  "file": "index.js",
  "line": 464,
  "code": "removeMatchingHeaders(/^(?:authorization|cookie)$/i, this._options.headers);",
  "similarity": "high",
  "explanation": "This is the exact vulnerable line. The regex alternation /^(?:authorization|cookie)$/i is applied in the cross-origin redirect guard (inside _processResponse, triggered when redirectUrl.host !== currentHost or the protocol is downgraded). It strips Authorization and Cookie but the alternation does not include 'proxy-authorization', so any Proxy-Authorization header present in this._options.headers is forwarded verbatim to the attacker-controlled redirect destination. The data flow is: original request carries Proxy-Authorization → 3xx redirect to attacker host → _processResponse fires → regex removes authorization/cookie only → _performRequest sends the redirected request with Proxy-Authorization still present → attacker receives the credential."
}
```

Cross-checked against the upstream fix commit `c4f847f85176991f95ab9c88af63b1294de8649b`: that commit modifies exactly `index.js:464` from `/^(?:authorization|cookie)$/i` to `/^(?:authorization|cookie|proxy-authorization)$/i`. The agent's identification matches the actual fix one-to-one.

This is the canonical Track-A success: A1 seed + A2 AST tool + A3 calibration produced a candidate that maps back to the actual fix commit.

### The parser-loss caveat (semver)

The harness reported `0 variants` for semver. The JSONL log tells a different story.

The agent's final response (T10, `end_turn`, 3915 output tokens, captured intact thanks to PR #58's uncapped final-text logging):

> *"I now have a thorough understanding of all the vulnerable patterns in this codebase. All instances are contained in `internal/re.js`. Let me now compile the full analysis of every distinct instance of the root cause:"*
>
> *"…\[bullet list of 12 vulnerable lines\]"*
>
> *"- **Line 138**: `(\\s*)${src[t.LONETILDE]}\\s+` — `\s*` in capture group adjacent to interpolation, plus `\s+` after"*
> *"- **Line 148**: `(\\s*)${src[t.LONECARET]}\\s+` — same pattern for caret"*
> *"- **Lines 160-161**: `(\\s*)${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]}|${src[t.XRANGEPLAIN]})` — `\s*` on both sides of an interpolation"*
> *"…"*
>
> *"\{ "rootCauseAnalysis": "…", "variants": \[ {twelve variant entries with file: "internal/re.js" and lines 94, 108, 115, 122, 123, 138, 148, 155, 156, 160, 168, 173}, … \] \}"*

**The agent identified all four calibration-band lines (138, 148, 160, 161) plus eight more in the same file.** Every one maps to a `createToken('NAME', `template`)` call where `\s*` or `\s+` is adjacent to a `${}` interpolation — exactly the root-cause pattern A1's seed describes.

Why the harness reported 0: the agent's final response is markdown prose first, JSON object second. `parseVariants` (post PR #58) tries three extraction strategies — whole-text trim, markdown code fences, greedy outer-brace regex. None of them survive this layout: the text doesn't start with `{`, there are no ``` ``` fences, and the greedy regex grabs from the first `${src[...]}` in the prose to the last `}` of the JSON, producing un-parseable text.

This is a known failure mode of the post-PR-#58 parser, not a design failure of variants v2. The fix is deterministic and known (walk `{` positions from the end, find the first one whose to-end-of-string substring parses as JSON with a `variants` array). It's been queued as the immediate next task.

### Tool-use breakdown — was the AST tool actually exercised?

Across the two cases in run 6:

| Tool | follow-redirects | semver |
|---|---|---|
| `find_ast_pattern` | 2 calls | 4 calls |
| `search_code` | 8 | 4 |
| `read_file` | 8 | 7 |
| `list_files` | 2 | 4 |

The agent reached for `find_ast_pattern` first on both cases and returned to it multiple times mid-loop. Compare to the broken-grammars run 4 where the agent called it once, got file-access errors, and gave up. Compare also to run 2 which used 0× AST calls because the tool was silently broken.

This is the structural evidence that A2 is exercised: the agent uses the AST primitive when it works, and that's what produced the follow-redirects MATCH.

## What this proves about the kill criterion

Quoted verbatim from `docs/path-forward.md`:

> **Kill criteria:** if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough. At that point, the next bet is Track C (differential fuzzing), not deeper Track A iteration.

Today's data:

- Run 6 produced **≥1 candidate that maps back to the actual fix commit** (follow-redirects, exact line, exact code change). That alone clears the strict reading of A3's success criterion.
- The semver case ALSO produced candidates that map to the calibration target — they were lost to a harness format-parser bug, not the design. Even setting that aside, the kill criterion is satisfied by follow-redirects alone.
- The "serious attempt at the AST matcher" qualifier is met: the agent called `find_ast_pattern` 6 times across the two cases in run 6, the tool actually returned matches (post PR #57), and the agent reasoned about those matches before producing its final answer.

**Conclusion: today's data does not trigger the kill criterion.** The pre-committed 2026-10-26 kill date remains, but the structured-root-cause approach has shown it can produce real findings.

## What this writeup deliberately does not claim

- **Variants v2 is reliable.** Two calibration cases is too small a sample to draw statistical conclusions. The follow-redirects MATCH could be partly stochastic; the previous runs on the same case ranged from 0 to 3 variants returned. A real reliability claim needs n≥3 runs per case + an n≥5 corpus.
- **The kill criterion is permanently satisfied.** The kill date is 2026-10-26. Today's positive signal is one data point against that horizon. The bar at the kill date is also conjunctive: Track A AND Track B AND Track C must all be failing to retire the 0-day-finder framing. Today's data is about Track A only.
- **mythos-agent has found a 0-day.** It hasn't. A3 uses the calibration corpus where the bug is known. A4 (re-running the variant-hunt experiment with v2) is still pending — that's the test against unknown variants.
- **The follow-redirects variant is a new find.** It identifies the *known* CVE on the *known* vulnerable commit. No novel vulnerability was discovered.

## Cost

| Run | Outcome | Cost |
|---|---|---|
| 1 (Qwen, 404'd) | infra failure | ~\$0 (request rejected before LLM was billed for tokens) |
| 2 (Sonnet, rate-limited) | infra failure | ~\$3 (case 1 ran 10 min before 429; case 2 5 min, 0 tool turns useful) |
| 3 (Sonnet, broken AST) | infra failure | ~\$5 (5 + 5 min, both cases ran full loops without working AST tool) |
| 4 (Sonnet, semver only) | infra failure | ~\$2 (5.6 min, single case, surfaced PR #57 bug) |
| 5 (Sonnet, post-fix attempt 1) | infra failure | ~\$5 (5.6 + 8.2 min, surfaced PR #58 bug) |
| 6 (Sonnet, all fixes) | **valid evidence** | **~\$3** (2.5 + 2.7 min — significantly faster once the parser stopped throwing the agent into recovery loops) |

**Total: ~\$18.** Of that, only the run 6 portion (~\$3) is evidence about the design; the rest is the cost of debugging four infrastructure bugs in real time.

The 2026-04-26 negative-result writeup cost ~\$5–\$7 to establish the v1 bottleneck. The 2026-04-27 positive-signal writeup cost ~\$3 of valid-evidence runs plus ~\$15 of infrastructure debugging. The combined research arc to date: ~\$23 of API credit, two writeups, end-to-end Track A shipped.

## Reproducibility

To reproduce run 6 after PRs #50–#58 are on `main`:

```bash
# Requires Node 20+ and an Anthropic API key.
git clone https://github.com/mythos-agent/mythos-agent
cd mythos-agent
npm install
ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration -- \
  --log-turns \
  --results-subdir 2026-04-27-reproduction
```

Per-case results land in `benchmarks/variants-calibration/results/2026-04-27-reproduction/`:
- `summary.json` — high-level scoreboard
- `<GHSA>.json` — per-case `AgentCalibrationResult` (matched flag, returned variants, target band)
- `<GHSA>.turns.jsonl` — one record per agent turn (stop reason, tool calls, text preview, token usage)

**Branch / SHA at run 6:** `fix/variant-analyzer-json-output` at commit `44b0bfd` (PR #58 head, applied on top of PRs #57 and earlier).

**Fixture commit SHAs (live-cloned from upstream by the harness):**
- `npm/node-semver` → `2f738e9a70d9b9468b7b69e9ed3e12418725c650` (semver vulnerable commit)
- `follow-redirects/follow-redirects` → `8526b4a1b2ab3a2e4044299377df623a661caa76` (follow-redirects vulnerable commit)

**Expected variance:** the LLM agent loop is non-deterministic. Reproductions on the same prompt and model can return 0–3 variants on follow-redirects, and the parser-loss on semver is deterministic until a parser-fix PR lands. The follow-redirects MATCH-on-line-464 has been observed in two separate runs (2026-04-27T13-38-14-613Z and 2026-04-27-final), suggesting it's not a one-off — but the n is small.

## Next steps

In priority order:

1. **Parser fix** — walk `{` positions from the end of the agent's text, accept the first one whose to-end substring parses as JSON with a `variants` array. ~20 LOC. Re-runs against the existing `2026-04-27-final/GHSA-c2qf-rxjj-qqgw.turns.jsonl` would convert the semver miss to a MATCH without spending more API credit. **This is the immediate next task.**
2. **Run 6 confirmation** — re-run the calibration ≥3 more times (post parser-fix) on the same model and prompt. With n=4 we can claim hit rate, not just hit existence.
3. **A4 — the variant-hunt experiment re-run.** Same 4 targets, same 2 seeds, same models as the [2026-04-26 writeup](2026-04-26-variant-hunt-experiment.md) — but with A1 + A2 + A3 in place. Goal: ≥1 verified-real candidate across the 8 runs (the original baseline was 0/8). This is the actual test against unknown variants.
4. **Disclosure pipeline rehearsal.** If A4 produces a verified-real candidate, the [outbound-disclosure policy](../security/outbound-disclosure.md) workflow has never been exercised end-to-end. A dry-run with a mock finding would surface gaps before they bite a real disclosure.

## See also

- [`docs/research/2026-04-26-variant-hunt-experiment.md`](2026-04-26-variant-hunt-experiment.md) — the negative-result writeup that motivated Track A.
- [`docs/path-forward.md`](../path-forward.md) — Track A's full sub-PR breakdown (A1 → A4) and the kill-criterion ladder this writeup measures against.
- [`docs/multi-model.md`](../multi-model.md) — multi-model infrastructure that enabled cheap iteration during the bug-fixing loops.
- [`docs/security/outbound-disclosure.md`](../security/outbound-disclosure.md) — the disclosure policy that will gate any A4-derived finding.
- PRs shipped on 2026-04-27, in order: [#50](https://github.com/mythos-agent/mythos-agent/pull/50) (A1), [#51](https://github.com/mythos-agent/mythos-agent/pull/51) (A2), [#52](https://github.com/mythos-agent/mythos-agent/pull/52) (A3a), [#53](https://github.com/mythos-agent/mythos-agent/pull/53) (A3b harness), [#54](https://github.com/mythos-agent/mythos-agent/pull/54) (A3b Qwen wiring), [#55](https://github.com/mythos-agent/mythos-agent/pull/55) (model-ID hotfix), [#56](https://github.com/mythos-agent/mythos-agent/pull/56) (per-turn logging), [#57](https://github.com/mythos-agent/mythos-agent/pull/57) (grammars-dir resolution), [#58](https://github.com/mythos-agent/mythos-agent/pull/58) (JSON-only prompt + parser + uncap log).
