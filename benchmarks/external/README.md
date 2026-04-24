# External Benchmarks

> **Status:** scaffold only. Individual benchmark runners land in
> follow-up PRs; this directory documents the target corpora and the
> apples-to-apples methodology so any third party can reproduce our
> numbers.

mythos-agent publishes scores on recognized external benchmarks so the
numbers are directly comparable to other SAST tools' published
results. We deliberately **do not** lead with the Sphinx Benchmark
here — it's a differentiator for AI-era vuln classes, but for the
"is this tool any good?" question, external corpora carry more weight.

## Target corpora

### 1. OWASP Benchmark v1.2

- **What:** 2,740 synthetic Java test cases across 11 CWEs, plus
  matching true-negative cases for false-positive measurement.
- **Repo:** <https://github.com/OWASP-Benchmark/BenchmarkJava>
- **Why run it:** it's the *de facto* citable benchmark. Nearly every
  commercial SAST tool publishes a score here, so our number drops
  into an existing comparison landscape.
- **Weakness:** synthetic, pattern-friendly, Java-only, last major
  update 2018. Overstates pattern-matching scanner accuracy on
  modern stacks. We publish the number with this caveat attached.
- **Scoring:** OWASP ships its own scoring script
  (`scorecard/createScorecards.py`). Reuse it verbatim — do not roll
  our own scorer.

### 2. CyberSecEval 3 (Meta)

- **What:** Meta AI's security evaluation suite. Includes real CVE
  repro tasks, autonomous cyber tasks, and code-vulnerability prompts.
  Maintained by Meta's AI research team; cited in Anthropic's
  vulnerability-research publications.
- **Repo:** <https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks>
- **Why run it:** modern (2024+), real CVEs, widely referenced by AI
  security researchers. Running on this positions mythos-agent in the
  AI-security-tool conversation, not just the classical SAST one.
- **What we run:** the static-analysis subset. The autonomous-cyber
  subset requires agent infrastructure that's out of scope.

### 3. Vul4J

- **What:** 79 reproducible real Java CVEs with vulnerable/fix commit
  pairs. Academic-grade; used in several vulnerability-detection
  research papers.
- **Repo:** <https://github.com/tuhh-softsec/vul4j>
- **Why run it:** bridge between OWASP Benchmark (synthetic) and the
  CVE replay harness (real but ad-hoc-curated). Vul4J's curation is
  third-party, which makes the "N of 79 caught" number resistant to
  "but you picked easy ones" criticism.

### 4. Juliet / NIST SARD (lower priority)

- **What:** NIST-maintained C/C++ and Java test suites.
- **Why this is lower priority:** C/C++ memory safety is not
  mythos-agent's wheelhouse. Worth running the Java subset only as
  a supplementary data point.

## Methodology

Every published comparison row follows these rules:

1. **Free/OSS tier only.** Compare against Semgrep CE (OSS rules),
   Snyk Code free tier, CodeQL (OSS queries), Trivy. Do not compare
   against paid enterprise tiers — that comparison is unreproducible
   and invites accusations of tuning.
2. **Default configuration.** Each tool runs with its default config.
   No tuning for the benchmark. If mythos-agent scores poorly with
   defaults, that's an honest data point.
3. **Same corpus checkpoint.** All tools scan the same commit of the
   benchmark repo. Commit hash goes in the results JSON.
4. **Published scoring script.** Use the benchmark's own scoring
   script where one exists (OWASP Benchmark, Vul4J). Do not invent a
   mythos-agent-friendly scorer.
5. **Failures disclosed.** Cases mythos-agent misses are listed in
   the results JSON, grouped by CWE. Hiding failures destroys
   credibility once a third party re-runs.

## Layout (planned)

```
benchmarks/external/
├── README.md           # this file
├── owasp-benchmark/
│   ├── run.ts          # clone + scan + feed into OWASP scorer
│   └── results/        # per-release results JSONs
├── cybersecevalval3/
│   ├── run.ts
│   └── results/
└── vul4j/
    ├── run.ts
    └── results/
```

Each subdirectory is its own follow-up PR. The runners share a helper
for invoking `runScan` against a cloned repo — that helper is
factored out of `benchmarks/cve-replay/run.ts` once the second runner
is written.

## Publishing cadence

- On every mythos-agent release: re-run all external benchmarks,
  commit results JSONs, update `docs/benchmarks/external-scores.md`.
- For comparison rows (Semgrep/Snyk/CodeQL): re-run quarterly, or
  immediately after any of those tools has a major release that
  changes their baseline.
- In the CHANGELOG, each release includes the benchmark-delta line:
  `v4.X.Y | OWASP TPR: 0.XX | CyberSecEval3: 0.XX | Vul4J: NN/79`.
