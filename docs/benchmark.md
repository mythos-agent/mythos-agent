# The Sphinx Benchmark

> **Status: Live scaffold, 4 cases.** The v0.1 runner ships under
> `src/scanner/__tests__/benchmark-scaffold.test.ts` and auto-discovers
> cases from `benchmark/cases/`. Every `npm test` run exercises the
> corpus against the wired deterministic scanners; a missing expected
> finding fails CI. The corpus grows incrementally — first ≥100 cases
> land in Q4 2026, full 500 by end of 2026, 1,000 by end of 2027.
>
> **License:** dataset CC-BY 4.0; runner code MIT.
>
> **Last reviewed:** 2026-04-19.

> **Related, not a replacement:** the Sphinx Benchmark is mythos-agent's
> in-house corpus for AI-era and MCP-era vuln classes. The
> complementary tracks are:
>
> - [`benchmarks/cve-replay/`](../benchmarks/cve-replay/README.md) —
>   real-world GHSA advisories replayed against the scanner at their
>   vulnerable commit. Answers "does it catch real CVEs?"
> - [`benchmarks/external/`](../benchmarks/external/README.md) —
>   OWASP Benchmark v1.2, CyberSecEval 3, Vul4J. Answers "how do our
>   numbers compare to Semgrep / Snyk / CodeQL?"
> - [`docs/benchmarks/external-scores.md`](benchmarks/external-scores.md) —
>   the dashboard readers get pointed to from the README. The Sphinx
>   Benchmark is a differentiator; external scores are the credibility
>   baseline.

## Why a new benchmark

Existing public vulnerability benchmarks are old, narrow, or both:

- **OWASP Benchmark** — last major update 2018; mostly Java; pattern-friendly fixtures that overstate scanner accuracy in modern stacks.
- **NIST SARD** — broad but inconsistent quality; many cases lack canonical "correct answer" labels.
- **MITRE Juliet** — C/C++ and Java; intentional-vuln synthetic code; doesn't match modern attack surface.
- **Vendor benchmarks** (Semgrep, Snyk, etc.) — useful internally but not third-party-runnable.

The Sphinx benchmark is designed to be:

1. **Modern** — built around 2024–2026 vulnerability classes, modern frameworks (TypeScript / Node, Python / FastAPI, Go, Rust), and AI-era attack surfaces (prompt injection sinks, MCP-server misconfig, unsafe LangChain patterns)
2. **Reproducible** — every case includes a vulnerable code fixture, the expected finding(s), the fix, and a runner that produces a pass/fail per scanner
3. **Comparable** — published per-release scanner accuracy JSON enables apples-to-apples comparison across versions and across scanners
4. **Community-contributable** — clear contribution path; CC-BY licensing
5. **Adversary-aware** — a portion of cases are deliberate true-negatives designed to elicit false positives from naïve scanners

## Scope

**In scope:**

- Application-layer vulnerabilities (CWE Top 25, OWASP Top 10, plus AI-misuse class)
- Static analysis fixtures (the vulnerability is detectable in source)
- Single-file and multi-file fixtures (chain detection)
- Languages: TypeScript, JavaScript, Python, Go, Rust, Java (in priority order)
- AI-era classes: prompt injection sinks, MCP server tool misuse, unsafe LangChain / LlamaIndex patterns, exposed model weights, JWT-with-LLM-claim leakage

**Out of scope:**

- Memory safety in C/C++ (Juliet covers this well)
- Pure cryptographic implementation flaws (specialized; better served by dedicated benchmarks)
- Runtime-only vulnerabilities (require DAST; tracked separately if/when the DAST track matures)
- Compiled-binary vulnerabilities

## Schema

Each case is a directory under `benchmark/cases/<id>/`:

```
benchmark/
└── cases/
    └── <id>/
        ├── case.yml            # Metadata
        ├── vulnerable/         # Code fixture(s) containing the vulnerability
        ├── safe/               # Optional: a corrected version of the same code
        └── README.md           # Human-readable explanation
```

`case.yml` schema (subject to revision via RFC before Q4 2026 lands).
This example is the actual shape of a shipped case — see
[`benchmark/cases/SPX-BENCH-0001/case.yml`](../benchmark/cases/SPX-BENCH-0001/case.yml)
for the original:

```yaml
id: SPX-BENCH-0001               # Stable identifier
title: JWT token persisted to browser localStorage
cwe: CWE-922                     # Real CWE; placeholders rejected
severity: medium                 # critical | high | medium | low | info
languages:
  - typescript
  - javascript
classes:                         # Attack class taxonomy
  - auth
  - jwt
  - insecure-storage
sources:                         # Where this case came from
  - type: canonical_pattern
    url: https://cwe.mitre.org/data/definitions/922.html
license: CC-BY-4.0
expected_findings:               # The ground truth
  - file: vulnerable/auth.ts
    rule_class: jwt-stored-localstorage
    severity: medium
notes: |
  JWTs stored in window.localStorage are readable by any script in
  the document — an XSS anywhere on the origin exfiltrates the token.
  The intended fix is HttpOnly cookies or an in-memory token with a
  silent refresh from a cookie-backed refresh token.
contributed_by: "@your-handle"
contributed_at: "2026-04-19"
```

The scaffold matches an expected finding against produced findings by
`f.location.file.endsWith(expected.file) && f.rule.includes(expected.rule_class)`
— so `rule_class` only needs to be a substring of the scanner's full
rule id (`"jwt-stored-localstorage"` matches `"jwt:jwt-stored-localstorage"`).

## Current corpus

As of the last-reviewed date, the corpus has **4 cases covering 4 distinct
wired deterministic scanners**:

| Case | Scanner | Rule class | CWE | Severity |
|---|---|---|---|---|
| [SPX-BENCH-0001](../benchmark/cases/SPX-BENCH-0001/README.md) | JwtScanner | `jwt-stored-localstorage` | CWE-922 | medium |
| [SPX-BENCH-0002](../benchmark/cases/SPX-BENCH-0002/README.md) | BusinessLogicScanner | `biz-role-escalation` | CWE-269 | critical |
| [SPX-BENCH-0003](../benchmark/cases/SPX-BENCH-0003/README.md) | SessionScanner | `session-insecure-cookie` | CWE-614 | high |
| [SPX-BENCH-0004](../benchmark/cases/SPX-BENCH-0004/README.md) | HeadersScanner | `header-csp-unsafe` | CWE-693 | high |

Next natural additions: SecretsScanner (the 5th scanner the v0.1 runner
exercises and currently without a benchmark case), then coverage of the
other wired scanners (PatternScanner rule classes, CryptoScanner,
PrivacyScanner, etc.) as dedicated cases rather than PatternScanner's
broader aggregate.

## Runner contract

The v0.1 runner (`src/scanner/__tests__/benchmark-scaffold.test.ts`)
enumerates every `benchmark/cases/SPX-BENCH-*` directory, loads each
`case.yml`, runs the wired deterministic scanners against the case
directory, and fails if any `expected_findings` entry has no matching
produced finding. Runs on every `npm test` / every CI push, so a
missing finding blocks merge.

Scanners evaluated in v0.1: SecretsScanner, JwtScanner, HeadersScanner,
SessionScanner, BusinessLogicScanner. PatternScanner + the AIAnalyzer
loop are deliberately excluded from v0.1 — they need a `MythosConfig`
and an LLM key respectively, which would turn the fast unit-test runner
into an integration test. Those paths rejoin when the full runner
(below) lands in Q4 2026.

The full runner (`benchmark/run.ts`, lands Q4 2026) will additionally produce:

- **Per-case result:** Pass (correct findings only), Partial (missed some, found others), Fail (no findings or all wrong)
- **Aggregate metrics:** True Positive Rate, False Positive Rate, Precision, Recall, F1, runtime per case
- **Output:** JSON committed to `docs/benchmark/results/<scanner>-<version>-<date>.json`

Sphinx-agent runs the benchmark on every release and commits its own results. Other scanners are run periodically (target: quarterly) for comparison rows. Independent re-runs are encouraged — the runner is MIT and the dataset is CC-BY.

## Per-release accuracy publication

For each mythos-agent release, the CHANGELOG includes a row:

```
v2.X.X (date) | TPR: 0.XX | FPR: 0.YY | F1: 0.ZZ | runtime: NN s | benchmark: SPX-BENCH-2026-Q4
```

Regression thresholds are wired into the [release-please workflow](../.github/workflows/release-please.yml) starting Q1 2027: a release that drops TPR by >2 points or raises FPR by >2 points blocks merge of the release-please PR until either an explanation lands in the PR description or the regression is fixed.

## Comparison rows (third-party scanners)

We publish comparison rows against:

- **Semgrep CE** — for the pattern-matching axis
- **Trivy** — for the dependency / IaC axis
- **OSV-Scanner** — for the dependency-vuln axis
- **Nuclei** — for the template-based DAST axis (where applicable to static cases)

These rows are **observations, not claims**. The methodology is identical across scanners; the runner is open; comparison results are reproducible. We do not claim mythos-agent "wins" — we publish numbers so users can decide.

## Contribution workflow

To contribute a case:

1. Pick a CWE not yet covered — see the [Current corpus](#current-corpus)
   table above; the audit list lands at `docs/benchmark/coverage.md`
   once it grows past a table.
2. Copy `benchmark/cases/_template/` to `benchmark/cases/SPX-BENCH-NNNN/` — next free number (current highest: 0004).
3. Fill `case.yml`, add the `vulnerable/` fixture, optionally a `safe/` corrected version, write `README.md`.
4. Run `npx vitest run src/scanner/__tests__/benchmark-scaffold.test.ts`
   locally. The new case is auto-discovered; a failing match produces
   a diagnostic listing every finding the scanners produced — use it
   to tune your `rule_class` assertion.
5. Open a PR with `[BENCH]` prefix in the title.
6. Reviewer checks: schema validity, license declaration, ground-truth correctness, no PII or secrets.

**Pitfalls observed in shipped cases** (see each case's README for
specifics):

- **Whole-corpus-aggregating scanners** (HeadersScanner's missing-header
  rules, which check that no file in the project emits the header) can
  be defeated by the scaffold scanning `vulnerable/` + `safe/` as one
  project. Prefer misconfig rules (`header-csp-unsafe`) over missing
  rules for HeadersScanner cases. See SPX-BENCH-0004 README.
- **Regex `.` does not cross newlines by default.** If the scanner's
  pattern requires two tokens on the same line (e.g., header name +
  unsafe value), put them on one line in the vulnerable fixture even
  if that means a long line. First SPX-BENCH-0004 attempt failed here.
- **Safe fixture content must not accidentally trigger the scanner's
  broader patterns.** BusinessLogicScanner's role-escalation rule
  has a broader pattern that fires when `role` / `isAdmin` / etc.
  appear near a `.update(…)` call; even a comment mentioning "role"
  in a safe fixture can false-positive. See SPX-BENCH-0002 README.

Once the bounty program activates ([`docs/bounty.md`](bounty.md)), benchmark contributions with reproducible PoCs are eligible for the $500 tier.

## Attribution and licensing

- **Dataset (`benchmark/cases/`):** CC-BY 4.0. Each case credits its contributor(s) in `case.yml` and in the per-case README.
- **Runner (`benchmark/run.ts` and supporting code):** MIT, matching the rest of the project.
- **Result JSONs (`docs/benchmark/results/`):** CC-BY 4.0.

External users of the dataset are required only to cite. Suggested citation:

> Mythos-Agent contributors. "The Sphinx Benchmark v\<X.Y\>." mythos-agent project, 2026. https://github.com/mythos-agent/mythos-agent/tree/main/benchmark

## Roadmap relationship

This benchmark is **B3** in the [strategic bets](../ROADMAP.md#2-strategic-bets). Year-by-year milestones:

- **2026:** schema + runner + first 500 cases. First mythos-agent FP rate measurement against the corpus. First comparison row vs Semgrep CE.
- **2027:** corpus expanded to 1000 cases. First external citation. AI-misuse class expanded. Annual update of the runner contract.
- **2028:** stability — the benchmark becomes load-bearing infrastructure that downstream tools reference. Schema versioning policy enforced.

## Open questions (RFC at schema lock-in)

- How are multi-file chain cases scored?
- How do we handle cases where two scanners both find the vulnerability but flag different lines?
- What is the policy for cases where a contributor's expected-findings are demonstrably wrong (correct the case? mark as disputed? remove?)
- Do we accept synthetic / LLM-generated cases at all, given their bias toward elicit-able patterns?

These get resolved in `docs/rfcs/NNNN-benchmark-schema-v1.md` (template at [docs/RFC-TEMPLATE.md](RFC-TEMPLATE.md)) before the schema is locked.

## References

- [OWASP Benchmark](https://owasp.org/www-project-benchmark/) — prior art (now aging)
- [NIST SARD](https://samate.nist.gov/SARD/) — federated dataset reference
- [MITRE Juliet Test Suite](https://samate.nist.gov/SARD/test-suites/112) — adjacent benchmark for C/C++ and Java
- [OSV-Schema](https://ossf.github.io/osv-schema/) — the model for ecosystem-standard data formats
- [Research agenda](research-agenda.md) — how this benchmark fits the broader research output

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial spec stub published. Schema and first 100 cases land Q4 2026. |
| 2026-04-19 | v0.1 scaffold + runner shipped. Corpus grew 1 → 4 cases (JWT / BusinessLogic / Session / Headers). Schema example updated to real SPX-BENCH-0001 shape. Contribution workflow gained a "pitfalls observed" section citing specific gotchas from the first four cases. |
