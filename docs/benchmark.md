# The Sphinx Benchmark

> **Status: Spec stub.** The benchmark dataset is being built incrementally through 2026. This document defines the schema, scope, methodology, and contribution rules. The first ≥100 cases land in Q4 2026 (per the H1 2026 Goals issue); the full 500 by end of 2026; 1,000 by end of 2027.
>
> **License:** dataset CC-BY 4.0; runner code MIT.
>
> **Last reviewed:** 2026-04-18.

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

`case.yml` schema (subject to revision via RFC before Q4 2026 lands):

```yaml
id: SPX-BENCH-0001               # Stable identifier
title: SQL injection in user search endpoint
cwe: CWE-89                      # Real CWE; placeholders rejected
severity: high                   # critical | high | medium | low | info
languages: [typescript]
classes:                         # Attack class taxonomy
  - injection
  - sql
sources:                         # Where this case came from
  - type: cve_repro
    cve: CVE-2024-XXXXX
    url: https://...
license: CC-BY-4.0
expected_findings:               # The ground truth
  - file: vulnerable/api.ts
    line_range: [42, 48]
    rule_class: sql-injection
    severity: high
notes: |
  Edge case: the query uses template literals with `${input}` interpolation
  rather than the more common string concatenation. Scanners that only check
  for `+` concatenation will miss this.
contributed_by: '@your-handle'
contributed_at: '2026-XX-XX'
```

## Runner contract

The benchmark runner (`benchmark/run.ts`, lands Q4 2026) executes a scanner against every case and produces:

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

1. Pick a CWE not yet well-covered (audit list lands at `docs/benchmark/coverage.md`)
2. Copy `benchmark/cases/_template/` to `benchmark/cases/SPX-BENCH-NNNN/` — next free number
3. Fill `case.yml`, add the `vulnerable/` fixture, optionally a `safe/` corrected version, write `README.md`
4. Run the runner locally to confirm mythos-agent's expected behavior on your case
5. Open a PR with `[BENCH]` prefix in the title
6. Reviewer checks: schema validity, license declaration, ground-truth correctness, no PII or secrets

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
