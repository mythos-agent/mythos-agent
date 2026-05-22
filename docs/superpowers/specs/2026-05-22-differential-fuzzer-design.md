# Design — Differential URL-Parser Fuzzer (Track C MVP)

**Date:** 2026-05-22
**Issue trail:** `docs/path-forward.md` Track C; the 2026-05-22 capability review named the differential fuzzer the highest-probability path to a novel 0-day. First Tier 1 capability after the Tier 0 bundle (PR #91).
**Status:** approved, pending implementation plan.

## TL;DR

Fuzz multiple URL parsers on the same crafted inputs and flag where they disagree on a security-critical field. Cross-parser disagreement on `hostname` / `protocol` / `port` is the root cause of SSRF-filter-bypass, open-redirect, and auth-bypass vulnerabilities. The MVP fuzzes three distinct URL-parsing implementations, compares their output, and runs LLM-assisted triage over the divergences.

## Background

`path-forward.md` Track C identifies differential fuzzing as the bug-finding methodology with a proven track record (Google Big Sleep's SQLite CVE-2025-6965 came from fuzzing with structured input). The 2026-05-22 capability review's methodology agent called it "the single highest-probability 0-day path" — the only execution-based, oracle-driven method on the roadmap, and the only one that needs no seed pattern.

URL parsers are the chosen first parser class: URL-parser-confusion is a well-documented, high-impact bug class — when two parsers in one request path disagree about a URL's host, the gap between them is exploitable (a security check sees `good.com`, the HTTP client connects to `evil.com`).

**Note on Track C's stated dependency:** `path-forward.md` says Track C "depends on Track B (sandbox)." This MVP does not. Fuzzing a parser runs *trusted package code* on *untrusted input* — the threat is a hang / ReDoS / OOM, not arbitrary code execution. Resource-limited worker threads (below) are the correct, sufficient safety model; full sandbox isolation is not required.

## Scope

### In scope

The differential fuzzer MVP: corpus, mutator, three parser adapters, worker-isolated execution, differential comparison engine, LLM-assisted triage, a benchmark-style runner, and tests.

### Out of scope

- Coverage-guided fuzzing (instrumenting the target parsers' code paths).
- Auto-PoC / exploit generation — that is Track B (sandbox + verification) territory.
- Parser classes other than URL (JSON, Markdown, etc.) — future Track C iterations.
- Promotion to a first-class `mythos-agent` CLI command — the MVP stays a benchmark-style harness, like `benchmarks/variants-calibration/`.

## Target parsers

Three distinct URL-parsing implementations:

| Parser | Source | Role |
|--------|--------|------|
| native `URL` | built into Node (WHATWG) | spec reference / oracle |
| `url-parse` | npm, ~40M weekly downloads, deliberately lenient, CVE history | headline target |
| legacy `url.parse` | Node's deprecated `url` module parser, still widely used | canonical "disagrees with WHATWG" logic |

One new devDependency: `url-parse`. The other two are built into Node.

Each parser is wrapped in an **adapter** that normalizes its output to a uniform shape:

```
ParserResult = {
  protocol?: string
  hostname?: string
  port?: string
  username?: string
  password?: string
  pathname?: string
  error?: string   // the parser threw
  hang?: true      // the parse exceeded the timeout
}
```

Adapters are the extension point — adding a fourth parser later is one new adapter.

## Components & file structure

New directory `src/dast/differential-fuzzer/`:

- `types.ts` — `ParserResult`, `Divergence`, `FuzzReport`, supporting types.
- `corpus.ts` — ~80–150 hand-curated URL-confusion seed patterns plus a loader. Families: embedded-`@` (`http://a@b@c`), backslash-vs-slash (`http://a\b`, `http:\\a`), missing-slash (`http:a.com`), tab/CR/newline injection, unicode / IDN homoglyph / fullwidth, control characters, port and userinfo tricks, IPv4/IPv6 oddities.
- `mutator.ts` — expands seeds into many inputs via a **seeded RNG** (deterministic → reproducible runs): character insertion/swap/duplication at confusion points, component splicing, case and encoding variation, length extension.
- `parsers.ts` — the three parser adapters implementing the uniform interface.
- `worker.ts` — the worker-thread parse runner.
- `engine.ts` — runs one input through all parsers, pairwise-compares, emits `Divergence[]`.
- `triage.ts` — LLM-assisted divergence categorization.
- `index.ts` — orchestration (corpus → mutate → engine → collect/dedup → triage → report).

Plus:
- `benchmarks/differential-fuzz/run.ts` — CLI entry point, wired to an `npm run benchmark:differential-fuzz` script (mirrors `benchmarks/variants-calibration/run.ts`).
- `src/dast/differential-fuzzer/__tests__/` — tests.

## Data flow

corpus → mutator (expand to N inputs) → engine: each input parsed by all three adapters **via a worker pool** with a per-call timeout → `ParserResult[]` per input → pairwise comparison on security-critical fields → `Divergence[]` → collector dedups/groups divergences by `(field, parser-pair, signature)` → triage (LLM categorizes each unique divergence *class*) → reporter writes a ranked JSON report + a human-readable summary.

Here **signature** is a normalized fingerprint of the disagreement — e.g. which confusion family the input came from plus the *kind* of value mismatch — so that thousands of inputs producing structurally-identical divergences collapse into one class that triage and the report operate on. One representative input is retained per class.

## Execution model — worker-thread isolation (Approach 1)

The fuzzer core (corpus, mutation, comparison, triage, reporting) runs in-process. The parse calls — the only untrusted-input-touching step — run in a **small persistent worker pool** (configurable size, default ~4):

- The main thread sends `{parserId, input}` to a free worker and starts a per-call timer (default 1s).
- Worker responds in time → `ParserResult` recorded.
- Timer fires first → the worker is **terminated** (it hung — ReDoS or infinite loop), the input is recorded as a **hang divergence** (a genuine CPU-DoS finding), and a replacement worker is spawned.

This treats a hung parser as a *finding* rather than a crash, survives it, and avoids both the fragility of pure in-process execution (a synchronous infinite loop cannot be interrupted in-process) and the per-call overhead of child processes.

## What counts as a divergence

For a single input, a `Divergence` is emitted when any pair of parsers disagrees. Three kinds:

1. **Field divergence** — two parsers return different values for a security-critical field. Ranked by field severity: `hostname` and `protocol` highest (SSRF / open-redirect / protocol confusion), then `port`, then `username` / `password` (credential confusion), then `pathname` (lowest).
2. **Throw divergence** — one parser throws, another succeeds on the same input.
3. **Hang divergence** — a parser exceeds the timeout while others complete.

Native `URL` is the spec reference: every divergence is labelled with which side matches WHATWG and which diverges.

## LLM-assisted triage

After dedup, each unique divergence *class* is sent to the LLM via the existing `createLLMClient` factory (which now benefits from the Tier 0 prompt-caching work). The model categorizes each class as:

- `spec-ambiguity` — harmless, both behaviors defensible (noise)
- `likely-exploitable` — a real SSRF / open-redirect / auth-bypass risk
- `dos` — a hang / resource-exhaustion finding

The final report ranks `likely-exploitable` and `dos` classes above `spec-ambiguity`. Triage failure (LLM error) degrades gracefully — the divergence is still reported, marked un-triaged, with a `console.warn` (consistent with the Tier 0 parsing-failure philosophy).

## Error handling

- A parser throwing is a normal, comparable outcome (captured in `ParserResult.error`).
- A parser hanging → worker timeout → hang divergence.
- A worker crash / OOM → caught by the pool, recorded, worker replaced.
- LLM triage failure → divergence reported un-triaged with a warning; the run still completes.

## Testing

- **Unit:** mutator output is deterministic under a fixed RNG seed; the engine emits a `Divergence` when fed stub parsers that deliberately disagree; the corpus loads and is non-empty; dedup/grouping collapses near-identical divergences.
- **Worker:** a deliberately-hanging stub parser is caught by the per-call timeout and recorded as a hang divergence (not a process crash).
- **Triage:** runs against a mock LLM client (no API cost in CI).
- **Offline integration:** a tiny corpus is run through the three real parser adapters; the test asserts the harness completes and emits a well-formed `FuzzReport` — it asserts the *harness works*, not any specific finding.

## Determinism & cost

The mutator uses a seeded RNG, so a run is fully reproducible from `(corpus, seed, count)`. LLM triage only fires on unique divergence *classes* (post-dedup) — a handful per run — and uses prompt caching, so a run costs roughly $1–3 of API credit.

## Success criteria

- The harness runs end-to-end and produces a ranked, LLM-triaged divergence report.
- Per `path-forward.md` Track C kill criterion: a real run producing **zero** divergences means the methodology has failed. URL parsers are well-known to diverge, so the real bar is whether triage surfaces **≥1 `likely-exploitable` divergence** worth manual confirmation.

## Risks & mitigations

- **Worker-pool complexity** — the pool with per-call timeout + hung-worker replacement is the most intricate part. Mitigation: it is isolated in `worker.ts` behind a simple `parse(parserId, input)` interface and unit-tested with a hanging stub.
- **Divergence flood** — URL parsers diverge on *many* inputs; an un-deduped report would be thousands of near-identical entries. Mitigation: the collector groups by `(field, parser-pair, signature)` so triage and the report operate on divergence *classes*, not raw hits.
- **Triage noise** — most divergences are spec-ambiguity. Mitigation: that is exactly what the LLM triage classifies out; the report ranks exploitable/dos above ambiguity.
- **`url-parse` version drift** — pin the devDependency so runs are reproducible.

## Testing & integration notes

- Existing tests (`npm test`) stay green; `npx tsc --noEmit` clean.
- Commits require a DCO `Signed-off-by:` trailer (`git commit --signoff`).
- Conventional-commits enforced (commitlint).
