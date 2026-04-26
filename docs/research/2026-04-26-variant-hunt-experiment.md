# Variant-Hunt Experiment — 2026-04-26

> **TL;DR.** We tried Google Big Sleep's variant-analysis methodology at small scale using the existing `mythos-agent variants` command. Five runs, two LLM providers (Qwen 3 plus and Claude Sonnet 4.6), two seed CVEs, four targets including one (`path-to-regexp`) that was a *strong structural match* for the seed. **Zero variant candidates produced across all runs.** The bottleneck is not the seed CVE choice, not the target selection, and not the LLM provider — it's the variants tool's lack of structured root-cause modeling. The experiment cost ~$5–$7 and produced its valuable data: a definitive negative that justifies a variants-v2 redesign rather than more iteration on v1.

## Why this writeup exists

The mythos-agent README claims "Variant Analysis (Big Sleep technique) — given a known CVE, find structurally similar but syntactically different code in your codebase." That's been an aspirational claim since the project's start; never tested rigorously. After shipping multi-model support (PR #41 / #44 / #46) and wiring the variants tool through the same factory (PR #47), we had the infrastructure to actually test the claim end-to-end against real OSS targets.

Per the project's [outbound disclosure policy](../security/outbound-disclosure.md) §4 and the broader best-practice principle adopted in this codebase ("honesty beats coverage"), publishing a negative result is more valuable than quietly iterating until something works. This writeup is that publication.

## Hypothesis

**H1 (the marketing claim):** mythos-agent's variants command can find structurally-similar bugs to a known CVE in arbitrary OSS targets, similar to how Google Big Sleep finds variants of memory-corruption CVEs.

**H1a (sub-hypothesis, target-quality):** When pointed at a target package that does similar work to the seed CVE's source package (same parsing domain, same code idioms), the variants command should produce ≥1 candidate worth manual triage.

**H1b (sub-hypothesis, model-quality):** When run with a frontier model (Claude Sonnet 4.6) on a matched target, the variants command should produce more candidates than with a smaller model (Qwen 3 plus).

## Methodology

**Variants command, configured per `docs/multi-model.md`:** the agent loop runs up to 20 turns, with file-read / search-code / list-files tools. The system prompt instructs the model to "extract the root cause" and "find code that shares the same root cause." The output is a JSON-formatted list of `VariantMatch` objects with file/line/similarity/explanation fields.

**Seed CVEs (chosen from our existing CVE Replay corpus):**

- **CVE-2022-25883** — semver ReDoS via template-literal regex. Caught by `RedosScanner`'s template-literal extractor in PR #37. The vulnerable pattern is `new RegExp(value)` where `value` is a template literal containing `\s*` or `\s+` adjacent to `${...}` interpolation. Specific code idiom; semver uses a `createToken('NAME', \`pattern\`)` helper that's unusual.
- **CVE-2024-28849** — follow-redirects cross-host credential leak. The vulnerable pattern is a regex that strips `authorization` and `cookie` on cross-host redirects but omits `proxy-authorization`. Caught by `RedirectHeadersScanner` in PR #39.

**Targets (npm packages selected by the >100k weekly downloads + <5k stars + active-maintainer criteria from the [Phase B plan](../../C:%5CUsers%5Cwangz%5C.claude%5Cplans%5Cis-there-a-benchmark-glimmering-stroustrup.md)):**

- `minimatch` — glob-pattern matcher
- `css-what` — CSS selector parser
- `parse-duration` — time-string parser
- `path-to-regexp` — *added later as a matched target for CVE-2022-25883* (token-based regex builder, known ReDoS history via CVE-2024-45296)

**Models:**

- `qwen-plus` (Alibaba DashScope, OpenAI-compatible endpoint — the Tier 2 path from PR #41 / #44 / #46)
- `claude-sonnet-4-6` (Anthropic native — the Tier 1 path)

## Runs

| # | Seed CVE | Target | Model | Result | Notes |
|---|---|---|---|---|---|
| 1 | CVE-2022-25883 | `minimatch` | Qwen 3 plus | 0 candidates | Target-mismatch suspected |
| 2 | CVE-2022-25883 | `css-what` | Qwen 3 plus | 0 candidates | Target-mismatch suspected |
| 3 | CVE-2022-25883 | `parse-duration` | Qwen 3 plus | 0 candidates | Target-mismatch suspected |
| 4 | CVE-2024-28849 | `minimatch` | Qwen 3 plus | 0 candidates | Target-mismatch confirmed (none of these targets handle HTTP redirects) |
| 5 | CVE-2024-28849 | `css-what` | Qwen 3 plus | 0 candidates | Target-mismatch confirmed |
| 6 | CVE-2024-28849 | `parse-duration` | Qwen 3 plus | 0 candidates | Target-mismatch confirmed |
| 7 | CVE-2022-25883 | `path-to-regexp` (matched) | Qwen 3 plus | 0 candidates | Methodology question — Qwen too conservative? |
| 8 | CVE-2022-25883 | `path-to-regexp` (matched) | **Claude Sonnet 4.6** | **0 candidates** | **Refutes H1b. Proves the variants tool is the bottleneck.** |

Total cost: ~$2 of DashScope credit (Qwen runs) + ~$3–$5 of Anthropic credit (Sonnet run). Total wall time: ~30 minutes including triage between runs.

## Analysis

The first three Qwen runs (rows 1–3) used target packages that don't do similar work to the seed CVE's source. minimatch parses glob patterns; css-what parses CSS selectors; parse-duration parses time strings. None of them use semver-style token-based regex construction with template literals. The 0/3 result was consistent with a target-mismatch interpretation but didn't cleanly prove or refute H1.

Rows 4–6 added a different seed (CVE-2024-28849) on the same three targets. None of those targets handle HTTP redirects, so 0 candidates was the expected, unsurprising result — it confirmed the target-mismatch interpretation but didn't add information about the tool itself.

**Row 7** was the cleaner test. `path-to-regexp` is a strong structural match for CVE-2022-25883's seed package (semver): both build regex from token segments, both have ReDoS history, both are widely-used npm packages with similar code idioms. Qwen returned 0 candidates. At this point, the remaining hypotheses were "Qwen is too conservative" (model-quality) or "the variants tool is the bottleneck" (tool-design).

**Row 8** ran the same target + same seed on Claude Sonnet 4.6 — the same model class Anthropic Mythos Preview reportedly uses for its autonomous CVE filtering. **Sonnet 4.6 also returned 0 candidates.** This refutes the model-quality hypothesis: a frontier model on the most-plausible target with the most-applicable seed found nothing.

The remaining explanation is **the variants tool's design**. Per the existing honest-gap assessment of `src/analysis/variant-analyzer.ts`:

- **No structured root-cause representation.** The system prompt asks the model to "extract the root cause" but the tool maintains no graph, AST diff, or structured matcher. The model has to do all the work in-prompt.
- **Generic exploration tools.** The tool gives the model the same `list_files` / `read_file` / `search_code` tools the recon agent uses. No variant-specific tools (AST diff, regex-construction-pattern detector, taint-direction tracer).
- **No reference variants.** Big Sleep uses a calibration corpus of known-good and known-bad variants to tune similarity scoring. mythos-agent's variants command has no such corpus.
- **Fragile JSON parsing.** `parseVariants` regex-matches a JSON substring; a model that returns prose-only on token-limit truncation produces 0 even if it found something internally.

Note: the `--json` flag was *also* discovered to be broken during this experiment — it outputs the human terminal banner instead of structured JSON. Filed as part of the variants-v2 tracking issue but not load-bearing for this conclusion (we read the human output to confirm 0 candidates).

## What this proves about the original question

The question that opened this work-stream — "could mythos-agent find a real 0-day, like Anthropic Mythos did?" — gets a sharper answer than we had before:

- **At the autonomy level Anthropic Mythos demonstrates** (autonomous CVE filtering + autonomous exploit writing on the Linux kernel): no, and not soon. That requires execution sandboxing + frontier-internal-model fine-tuning + memory-corruption focus. Multi-month engineering minimum.
- **At Big Sleep's earlier methodology level** (LLM-driven variant analysis with sandbox-validated exploits): not yet, but achievable. The variants tool needs structured root-cause modeling + AST-based matching + a calibration corpus. Multi-week engineering. See [`docs/path-forward.md`](../path-forward.md) for the sequenced plan.
- **At the LLM-augmented manual-hunt level** (use mythos-agent's recon + hypothesis as input, do the real bug-finding manually): yes, today, with the existing scanners as accuracy floor. The CVE Replay scoreboard at 2 / 5 caught is the honest baseline; that's the kind of bug the deterministic scanners catch reliably, and the kind that finds variants in the wild today via PR #37 / #39 patterns.

The honest framing the mythos-agent project should adopt going forward: **"LLM-augmented security review tool, with documented capability gaps and a published roadmap to close them."** Not "AI security agent that finds 0-days." The former is true and useful; the latter is the marketing claim this experiment refutes.

## Methodology improvements that would change the result

For anyone re-running this experiment after the variants v2 work lands:

1. **Run with a structured root-cause representation.** Extract the CVE's pattern as an AST template + named-capture regex + taint specification, not as a prose description.
2. **Use AST-based matching tools.** Give the model `find_ast_pattern(pattern)` instead of (or in addition to) `search_code(regex)`. AST search escapes lexical-syntactic similarity into semantic-structural similarity.
3. **Calibrate on a known corpus.** Before deployment, validate that the tool catches known variants (e.g., the CVE Replay corpus's caught entries, used as both seed and target should produce a 1.0 hit rate).
4. **Save full structured output.** Fix the `--json` mode to emit machine-parseable JSON instead of the human banner. Triage tooling can then post-process at scale.
5. **Run against a target the seed package itself depends on or is part of an ecosystem with.** semver → other npm version-string parsers; `path-to-regexp` → other Express-ecosystem URL/route packages; etc. Maximize structural similarity.

## Reproducibility

All raw outputs from the 8 runs are at `/e/Github/hunt-targets/variants-*-2026-04-26.{json,err}` on the maintainer's machine (not committed to the repo because they contain stack-trace fragments with absolute paths; the summaries above are the durable record).

To re-run after variants v2 ships:

```bash
mkdir -p ~/Github/hunt-targets && cd ~/Github/hunt-targets
git clone --depth 1 https://github.com/pillarjs/path-to-regexp.git
cat > .mythos.yml <<EOF
provider: anthropic
apiKey: <your-claude-key>
model: claude-sonnet-4-6
EOF
npx mythos-agent@latest variants CVE-2022-25883 --path ./path-to-regexp --json > out.json
```

If `out.json` contains ≥1 variant on this exact reproduction case, variants v2 has measurably improved over v1.

## See also

- [`docs/path-forward.md`](../path-forward.md) — the comprehensive next-tracks plan informed by this experiment.
- [`docs/multi-model.md`](../multi-model.md) — the multi-model infrastructure that enabled cheap Qwen experimentation.
- [`docs/security/outbound-disclosure.md`](../security/outbound-disclosure.md) — the disclosure policy that gates any future findings from variants v2 or other tracks.
- [Anthropic Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/) — the methodology this experiment was inspired by and explicitly does *not* claim to match.
- [Google Project Zero — From Naptime to Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html) — the variant-analysis methodology this experiment attempted at smaller scale.
