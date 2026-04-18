# Research Agenda

What mythos-agent contributes back to the field of open security research, in addition to being a usable tool.

> **Why publish this.** The Garak (NVIDIA) playbook — peer-reviewed paper plus DEF CON slides — drove adoption faster than the tool's features did. For mythos-agent to be the *open Mythos-Agent*, it should add to the literature, not just consume from it.
>
> **Last reviewed:** 2026-04-18.

## Headline contributions

These are the artifacts the project commits to producing over the 3-year arc, in priority order.

### 1. The Sphinx benchmark — 500 → 1000 vulnerabilities (2026 → 2027)

**Artifact:** A curated, reproducible vulnerability dataset published at `docs/benchmark.md` and `benchmark/` with CC-BY licensing. Mix of CVE reproductions, intentional-vuln apps (e.g., DVWA, OWASP Juice Shop derivatives), and community-contributed cases.

**What it enables:** quantitative comparison between scanners (mythos-agent vs Semgrep CE vs Trivy vs OSV-Scanner) on a public, third-party-runnable corpus. Per-release accuracy JSON committed to the repo at `docs/benchmark/results/<version>.json`.

**Why this is novel:** existing benchmarks (OWASP Benchmark, NIST SARD) are old or narrow. A modern, growing, AI-friendly dataset doesn't exist as a community resource.

**Success metric:** cited in ≥1 external security research paper or blog post by end of 2027.

### 2. Hypothesis-driven agent architecture paper (2027)

**Artifact:** Workshop paper describing the 4-phase architecture (Recon → Hypothesis → Analyze → Exploit) implemented in `src/agents/`, with empirical results on the Sphinx benchmark.

**What it argues:** that hypothesis-first agent loops outperform single-pass scanners on novel-vuln discovery, and that the gain is measurable.

**Target venue:** USENIX Security WOOT 2027, or DEF CON AI Village 2027. WOOT prefers reproducibility evidence; DEF CON prefers demonstrable PoCs. We optimize for both.

### 3. Prompt-engineering patterns for security reasoning (2026 → 2027)

**Artifact:** A documented analysis of the prompts in `src/agent/prompts.ts` — what system prompts work, what tool-use schemas avoid common failure modes (drift, hallucinated CWEs, schema escapes), what reasoning structures detect particular vulnerability classes.

**What it adds:** there is no public reference for "good prompts when the LLM's job is security analysis." Anthropic's, OpenAI's, and Google's prompt guides are general; security-specific patterns sit inside companies' closed systems. A public reference is a force multiplier for adjacent OSS projects.

**Form:** living document at `docs/research/prompts.md` (lands H2 2026); accompanying blog post; data backing the claims is the Sphinx benchmark.

### 4. Empirical study: AI-augmented vs deterministic taint graphs (2027)

**Artifact:** A controlled study comparing mythos-agent's deterministic taint engine (B1 in [ROADMAP.md](../ROADMAP.md#2-strategic-bets)) against an AI-only baseline on the Sphinx benchmark. Variables: false-positive rate, false-negative rate, runtime, cost.

**Why this matters:** the field has moved fast on AI-only analysis (LangChain, LlamaIndex security tooling) and assumed it dominates classical methods. We have no idea whether the assumption holds. mythos-agent is well-positioned to provide the empirical answer because it implements both paths.

**Outcome:** publishable result either way. If hybrid wins, validates the architecture. If AI-only wins, redirects the project's engineering effort.

### 5. Multi-agent reasoning evaluation harness (2027 → 2028)

**Artifact:** An evaluation framework + public schema for measuring *agent pipelines* on security tasks. Garak evaluates standalone LLMs. Semgrep evaluates rules. **Nothing** evaluates agent pipelines.

**Why we should own this:** the schema would, like OSV-Schema, become an ecosystem standard if published CC0. Adjacent projects (Garak, AVID, AI Vulnerability Database) would adopt it because there is no competing standard.

**Form:** a typescript / python library at `tools/agent-eval/`; schema published CC0 at `schema/agent-eval.json`; reference implementations evaluating mythos-agent, Garak, and one other agent on the Sphinx benchmark.

### 6. Cross-tool reasoning-trace schema (2028)

**Artifact:** OSV-Schema-equivalent for agent reasoning evidence. When mythos-agent (or another tool) produces a finding, the chain of reasoning that led to it should be expressible in a portable, machine-readable format other tools can consume.

**Why this matters:** today, every scanner outputs findings in incompatible formats. A reasoning-trace schema would let a downstream auditing tool answer "did the finding's evidence hold up under reanalysis?" without rerunning the scanner.

**Form:** schema published CC0; reference implementation in mythos-agent's report layer.

## Target venues

| Venue | What works there | Cadence |
|---|---|---|
| **DEF CON AI Village** | PoC demos, reproducible attacks, slide decks | Annual (August) |
| **DEF CON Tool Demos** | New tools and significant new capabilities of existing tools | Annual (August) |
| **Black Hat Arsenal** | Tool releases with hands-on community access | Annual (August) |
| **USENIX Security WOOT** | Workshop papers; experimental results; offensive technique deep-dives | Annual (August, co-located with USENIX Security) |
| **NDSS Workshop on Binary Analysis Research (BAR)** | Static / dynamic analysis innovations | Annual (February / March) |
| **academic partnership** | Joint authorship on benchmark-using papers | Continuous, by relationship |

We deliberately do **not** target:

- Industry conferences without published proceedings (RSA, vendor events) — the work is intended for cited reference, not for marketing
- Bug bounty platforms — the project is a tool for finding vulns in scanned code, not a bug-bounty submission

## How research output is reviewed

Per [`docs/RFC-TEMPLATE.md`](RFC-TEMPLATE.md): any research output that names mythos-agent as a primary contributor (paper, conference talk, dataset release) goes through a lightweight RFC. The RFC publishes the abstract and methodology a week before submission, allowing the community (especially co-authors) to preview and object.

## Authorship and attribution

Default authorship order on mythos-agent papers:

1. The lead investigator (whoever led the work)
2. The lead maintainer of mythos-agent (because the artifact is a project asset)
3. Other contributors in order of measurable contribution

Authorship may always be negotiated downward by senior contributors. Contributors may always decline authorship.

## Funding interaction

Research output is a recognized deliverable category for [Sovereign Tech Fund](sustainability/funding.md#3-sovereign-tech-fund-germany) and NLnet NGI Zero applications. The benchmark dataset and the agent-evaluation harness are particularly well-suited to grant-funded delivery because they have clear deliverables and public artifacts.

## References

- [Garak: arXiv 2406.11036](https://arxiv.org/abs/2406.11036) — the playbook we're following
- [AI Vulnerability Database (AVID)](https://avidml.org/) — adjacent ecosystem
- [OSV-Schema](https://ossf.github.io/osv-schema/) — the ecosystem-defining schema model
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/) — prior art for vulnerability benchmarks (now aging)
- [ROADMAP.md § Strategic bets](../ROADMAP.md#2-strategic-bets)

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication. |
