# External Benchmark Scores

> **Status:** template. Numbers land once
> `benchmarks/external/*/run.ts` runners ship. Methodology is frozen
> (see [`benchmarks/external/README.md`](../../benchmarks/external/README.md)):
> free/OSS tier only, default config, published scorers, failures
> disclosed.

This page is the single URL a prospective user gets when they ask "is
mythos-agent any good?" It answers with numbers on benchmarks anyone
can re-run.

## Current release: v4.0.1 (2026-04-24)

| Tool | OWASP Benchmark v1.2 (TPR / FPR / F1) | CyberSecEval 3 (F1) | Vul4J (caught / 79) | CVE Replay (caught / N) |
|---|---|---|---|---|
| **mythos-agent v4.0.1** (deterministic scanners only) | _pending_ | _pending_ | _pending_ | **0 / 5** |
| Semgrep CE (OSS rules) | _pending_ | _pending_ | _pending_ | _pending_ |
| Snyk Code (free tier) | _pending_ | _pending_ | _pending_ | _pending_ |
| CodeQL (OSS queries) | _pending_ | _pending_ | _pending_ | _pending_ |
| Trivy | _pending_ | _pending_ | _pending_ | _pending_ |

Numbers fill in as each runner lands. Each row is reproducible against
the exact commit hashes published in the per-benchmark results JSONs
under `benchmarks/external/<benchmark>/results/`.

The `0 / 5` CVE Replay number for v4.0.1 is honest baseline data from
five observational cases spanning four scanner classes:

| GHSA | CVE | Package | Bug class | Why current scanners miss it |
|---|---|---|---|---|
| GHSA-9wv6-86v2-598j | CVE-2024-45296 | path-to-regexp | ReDoS | Vulnerable regex is constructed dynamically; RedosScanner only inspects static literals |
| GHSA-c2qf-rxjj-qqgw | CVE-2022-25883 | semver | ReDoS | Regex is defined via `new RegExp(src[...])` with concatenated source strings RedosScanner's extractor doesn't resolve |
| GHSA-cxjh-pqwp-8mfp | CVE-2024-28849 | follow-redirects | Cross-host credential forwarding | No deterministic scanner covers this class; needs a new rule |
| GHSA-hjrf-2m68-5959 | CVE-2022-23541 | jsonwebtoken | JWT key-type confusion | JwtScanner rules target JWT *usage* patterns, not sign/verify implementation bugs |
| GHSA-35jh-r3h4-6jhm | CVE-2021-23337 | lodash | Template / command injection | lodash.js is a single megafile; current scanners don't trace `template()` argument flow |

`fix-clean: 5 / 5` means the scanners don't false-positive on any of
the fix commits either — zero regressions on patched code. The value
of this baseline is exactly that it surfaces *where* coverage is
lacking, case-by-case. Re-run with `npm run benchmark:cve-replay`.

## How to interpret this table

- **TPR (true positive rate):** of the intentionally-vulnerable cases,
  what fraction the tool flagged. Higher is better.
- **FPR (false positive rate):** of the intentionally-safe cases, what
  fraction the tool flagged. Lower is better.
- **F1:** harmonic mean of precision and recall. Single number to
  compare tools, but sensitive to the benchmark's class balance.
- **Vul4J caught:** of 79 reproducible real Java CVEs, how many the
  tool flagged at the vulnerable commit.
- **CVE Replay caught:** of the cases in
  [`benchmarks/cve-replay/cases/`](../../benchmarks/cve-replay/cases/),
  how many the tool catches at the vulnerable commit and no longer
  flags at the fix commit.

None of these metrics individually is sufficient. A tool that scores
well on OWASP Benchmark but fails Vul4J is overfit to synthetic
fixtures; the reverse is overfit to CVE detail. Look at the row, not a
single cell.

## Honest notes on where mythos-agent is weak

_Populate as runners land with real numbers, per the "failures
disclosed" rule in the methodology._

## Sources

- [`benchmarks/external/README.md`](../../benchmarks/external/README.md)
  — methodology and corpus descriptions.
- [`benchmarks/cve-replay/README.md`](../../benchmarks/cve-replay/README.md)
  — the complementary real-world CVE replay harness.
- [`docs/benchmark.md`](../benchmark.md) — the Sphinx Benchmark, which
  covers AI-era and MCP-era vuln classes not represented in the
  external corpora.
