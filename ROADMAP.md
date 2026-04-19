# mythos-agent Roadmap

> The multi-year strategic frame for the **Mythos-Agent** — see [VISION.md](VISION.md) for the north star.
> The active 6-month working plan lives in the pinned GitHub Issue **`[Roadmap] mythos-agent H1 2026 Goals`**.
> This document is refreshed annually; material changes go through an [RFC](docs/rfcs/).

**Status:** v3.1.0 (April 2026) · MIT · TypeScript · single maintainer building toward a multi-maintainer team.
**Reading time:** ~10 minutes for the full document. Section 1 alone gives you the gist.

---

## 1. Vision in one paragraph

mythos-agent aims to be the open-source equivalent of an autonomous security research agent: a tool that reasons about a codebase the way a senior pentester would — generating hypotheses, navigating evidence, chaining individual findings into real attack paths, and proving exploitability. It is not a replacement for Semgrep, CodeQL, or Snyk; it integrates them where appropriate and competes on the axis those tools do not occupy: **autonomous reasoning on open code**. See [VISION.md](VISION.md) for the full framing and the capability arcs that define each year.

| Axis | Semgrep | CodeQL | Snyk | Nuclei | mythos-agent |
|---|---|---|---|---|---|
| Pattern matching | Best-in-class | Strong (manual queries) | Good | Template-based | Integrates Semgrep + adds AI reasoning |
| Cross-file taint | Pro tier (paid) | Strong, complex setup | Limited | None | Deterministic graph + AI (in progress) |
| Business logic | No | No | No | No | **Yes — AI hypothesis generation** |
| Vuln chaining | No | No | No | No | **Yes — graph + AI** |
| Dynamic analysis | No | No | No | Templates | **AI-guided fuzzing (early)** |
| Validated remediation | Limited | No | Fix PRs | No | **In progress** |
| Local LLMs | n/a | n/a | n/a | n/a | **Yes — Ollama / vLLM** |

---

## 2. Strategic bets

Four multi-year bets that define the project's arc. Each survives replanning; each has a single success metric.

**B1 — Deterministic semantic core.** Move taint and call-graph construction out of AI prompts (currently `src/agent/taint-tracker.ts`) and into graph algorithms (`src/analysis/taint-engine.ts`, `src/analysis/call-graph.ts`). The AI then reasons *over* the graph rather than building it. **Success metric:** false-positive rate <10% on the published 500-vuln benchmark by end of 2026.

**B2 — Persistent codebase knowledge graph.** Cross-run memory of entry points, auth boundaries, data stores, trust boundaries, so multi-turn reasoning accumulates across scans. **Success metric:** the second scan of a repo runs 3× faster than the first and surfaces at least one cross-reference finding the first missed.

**B3 — Novel-vuln benchmark.** A curated, CC-BY-licensed dataset of 500 vulnerabilities (growing to 1000) for measuring scanner accuracy. Mix of CVE reproductions, intentional-vuln apps, and community-contributed cases. **Success metric:** cited in at least one external security research paper or blog post by end of 2027.

**B4 — Validated remediation pipeline.** `src/agent/fix-validator.ts`: apply patch → generate test → run test → re-scan → report. **Success metric:** 70%+ of AI-generated fixes pass the validation pipeline in self-measurement by end of 2028.

---

## 3. Strategic themes

Three multi-year themes. Themes are undated; stages advance when the work is ready.

### Theme A — Foundation & Depth *(stage: in progress through H2 2026)*

Deterministic taint and call graphs. Tests for every CLI command. CWE Top 25 coverage audited across all 49 scanners. Stub rules in `src/rules/registry.ts` and `CWE-XXX` placeholders in `src/agent/prompts.ts` resolved. Supply-chain hardening per Section 11. Quantified accuracy commitments published per release (see B3).

**What a user gains as Theme A advances:** a scanner that can be trusted on real codebases — measurable false-positive rates, reproducible benchmarks, signed releases, SBOMs.

### Theme B — Autonomy & Discovery *(stage: experimental through 2026, stabilizing 2027)*

Persistent codebase knowledge graph. 4-phase agent (Recon → Hypothesis → Analyze → Exploit) with backtracking. Vulnerability chain engine upgraded from AI-only to graph + AI. Novel-vuln benchmark expanded to 1000 cases. Targeted detection for AI-misuse risks (prompt-injection sinks, unsafe LangChain patterns, MCP-server misconfig).

**What a user gains as Theme B advances:** the ability to ask mythos-agent to *hunt* — to investigate autonomously and report what it explored, not just what it matched.

### Theme C — Ecosystem & Scale *(stage: 2027–2028 horizon)*

Cross-system / monorepo / trust-boundary analysis. Validated remediation pipeline general availability (see B4). Scanner-plugin SDK published with cookie-cutter examples. Research partnerships and at least one academic collaboration. Governance transition to a Technical Steering Committee (see Section 6). Y2 sustainability decision gate resolved (see Section 9).

**What a user gains as Theme C advances:** a tool that scales from a single service to a polyglot enterprise monorepo, and a community big enough to outlive any single maintainer.

---

## 4. Active 6-month plan

The active working plan is the pinned GitHub Issue **`[Roadmap] mythos-agent H1 2026 Goals`** (link added on issue creation). H1 2026 buckets, with concrete deliverables tied to file paths:

| Bucket | Deliverable | Where | Status |
|---|---|---|---|
| Core hardening | Deterministic taint graph v1 | `src/analysis/taint-engine.ts` | in progress |
| Core hardening | 80% test coverage across 44 CLI commands | `src/cli/commands/__tests__/` | 7/44 smoke; 346+ tests across core/config/mcp/server/agents/chain/agent/rules/dast (parallel track) |
| Core hardening | Disambiguate placeholder strings to reduce Day-1 visitor confusion | `src/agent/prompts.ts`, `src/rules/registry.ts` | in progress |
| Core hardening | Single-source scanner orchestration (CLI ↔ HTTP API parity) | `src/core/run-scan.ts` | ✅ shipped — `runScan()` unifies both call sites; 15 scanners wired, drift-prevented by `wiring-invariant.test.ts` |
| Core hardening | Sphinx Benchmark v0.1 scaffold | `benchmark/cases/`, `src/scanner/__tests__/benchmark-scaffold.test.ts` | ✅ shipped — 5 cases covering JWT / BusinessLogic / Session / Headers / Secrets; drift-prevented by scanner-coverage invariant |
| Core hardening | 4.0 branding layer (`mythos_*` MCP tools, `MythosConfig`, `.mythos.yml`) with legacy `sphinx_*` aliases | `src/mcp/server.ts`, `src/types/index.ts`, `src/config/config.ts` | ✅ shipped — dual-probe back-compat live through 3.x; 4.0 drop is grep-and-delete |
| Core hardening | LLM-mock harness for agentic-loop testing | `src/agent/__tests__/analyzer-loop.test.ts` | ✅ shipped — AIAnalyzer DI + scriptable mock client; lift to shared util when next AI-loop test lands |
| Compliance | OpenSSF Best Practices Badge — Passing | bestpractices.dev | drafted, targeted June 2026 |
| Compliance | EU CRA stance published | `docs/security/cra-stance.md` | ✅ shipped |
| Compliance | SECURITY.md SLAs (Checkov-style) | `SECURITY.md` | ✅ shipped |
| Compliance | SARIF 2.1.0 JSON-Schema conformance | `src/report/__tests__/sarif-schema.test.ts` | ✅ shipped |
| Supply chain | Sigstore signing + SBOM per release | `.github/workflows/` | ✅ shipped |
| Supply chain | Actions pinned to commit SHAs + harden-runner + DCO | `.github/workflows/` | ✅ shipped |
| Supply chain | Deterministic LLM calls (temperature=0 pinned) | `src/agent/providers/*` | ✅ shipped |
| Community | Mythos-Agent Pioneers leaderboard | `docs/pioneers.md` | drafted |

H2 2026 will be opened as a new pinned issue in July 2026 and will lead with knowledge-graph v1 and agent test harness. Items in the active issue use the 🙋 marker when a champion is wanted; this is the primary contributor on-ramp for high-leverage work.

---

## 5. Contributor on-ramp

The full ramp lives in [CONTRIBUTING.md](CONTRIBUTING.md). Summary by entry point:

- **`good-first-issue` — scanner rule.** Add a rule for a CWE not yet covered. Target file under `src/scanner/*-scanner.ts`.
- **`good-first-issue` — test.** Pick one of the 44 CLI commands with no test yet, under `src/cli/commands/`. Templates and patterns live alongside existing scanner tests.
- **`good-first-issue` — docs.** Tutorials, examples, fixes.
- **`good-first-issue` — integration.** Wrap an additional external tool alongside the existing Semgrep / Gitleaks / Trivy / Checkov / Nuclei integrations in `src/tools/`.
- **`help-wanted` — analysis.** Deterministic taint graph, call graph, type resolver. Requires dataflow background.
- **`help-wanted` — agent.** Multi-turn reasoning, knowledge graph design. Requires LLM-application experience.
- **🙋 in pinned Goals issue.** A specific in-flight item where a champion is wanted.

The maintainer path stays at the existing 5+ non-trivial PRs threshold from [GOVERNANCE.md](GOVERNANCE.md), now mapped to areas (scanner / analysis / CLI / agents) so specialization is possible.

Recognition layer: **[Mythos-Agent Pioneers](docs/pioneers.md)** — auto-updated leaderboard; profile cards for top contributors; opt-in conference invite list. A cash-bounty program is *drafted but inactive* and activates on first corporate user OR $5K/month recurring sponsorship; see [docs/bounty.md](docs/bounty.md).

---

## 6. Governance evolution

Three phases. Triggers — not dates — drive transitions. Full text appended to [GOVERNANCE.md](GOVERNANCE.md).

- **Phase 1 — Benevolent maintainer (current).** Solo lead per [MAINTAINERS.md](MAINTAINERS.md). Valid while active maintainers <3.
- **Phase 2 — Multi-maintainer.** Trigger: 3+ active maintainers. Area-specialized maintainers (scanner / analysis / CLI / agents). Lazy consensus continues.
- **Phase 3 — Technical Steering Committee.** Trigger: 5+ active maintainers OR commercial posture declared. 3–5 seats: at minimum one lead, one analysis-area, one scanner-area; remaining seats by lazy consensus. Scope: roadmap direction, breaking changes, license posture, commercial gate decisions, conflict resolution. Quarterly meeting notes in `docs/tsc-meetings/`. The TSC cannot unilaterally relicense the core; the existing 14-day consensus window still binds.

**License firewall.** Scanner code contributed under MIT remains MIT in perpetuity. Any future commercial differentiation will come from new code under a separate license, never from relicensing existing OSS code. This sentence is the primary protection against an Opengrep-style fork.

**Trademark.** The `mythos-agent` name is currently held by the lead maintainer personally. Future transfer to a fiscal host (such as Open Source Collective) is on the table once Phase 2 is reached.

---

## 7. Community & momentum metrics

Measured quarterly via [docs/health-metrics.md](docs/health-metrics.md) using CHAOSS Starter Project Health metrics.

| Metric | 2026 target | 2027 target | 2028 target |
|---|---|---|---|
| GitHub stars | 1,000 | 3,000 | 7,000 |
| External contributors with merged PRs | 10 | 25 | 50 |
| Active maintainers | 1 | 3 | 5 |
| npm weekly downloads | 500 | 2,000 | 5,000 |
| CWE Top 25 coverage | 100% | 100% | 100% |
| FP rate on benchmark | <15% | <10% | <7% |
| Conference talks / papers | — | 1 talk | 1 talk + 1 workshop paper |
| CVEs disclosed by mythos-agent users | — | 5 | 15 |

Opt-in scan telemetry (count only, no content) lands per [docs/telemetry.md](docs/telemetry.md).

---

## 8. Research agenda

Detailed in [docs/research-agenda.md](docs/research-agenda.md). Headline contributions mythos-agent intends to make to the field:

- **Benchmark dataset** (500 → 1,000 vulnerabilities, CC-BY).
- **Prompt-engineering patterns for security reasoning** — `src/agent/prompts.ts` published as a documented reference, with empirical analysis of which patterns work.
- **Hypothesis-driven agent architecture** — workshop paper on the 4-phase pipeline.
- **Empirical study** on AI-augmented vs deterministic taint graphs.
- **Multi-agent reasoning evaluation harness** — no comparator publishes one. Garak evaluates LLMs; Semgrep evaluates rules; nobody evaluates *agent pipelines for security tasks*. mythos-agent will publish methodology and a public schema.
- **Cross-tool reasoning-trace schema** — an OSV-Schema-equivalent for agent reasoning evidence, publishable CC0.

Target venues: DEF CON AI Village (2027), Black Hat Arsenal (2027), USENIX Security WOOT (2027 or 2028), at least one academic collaboration offering the benchmark as shared resource.

---

## 9. Sustainability & commercial posture

- **2026 — pure OSS.** [GitHub Sponsors](https://github.com/sponsors/zhijiewong). [Open Collective](https://opencollective.com) via Open Source Collective fiscal host. Apply Sovereign Tech Fund and NLnet NGI Zero (security-tooling tracks). Apply OSTIF for security audit grant once at Silver badge.

- **2027 — decision gate.** Open-core is considered only if **all three** conditions are met:
  1. 3,000+ GitHub stars
  2. ≥3 production deployments reported
  3. Maintainer team ≥3 people

  Public commitment regardless of gate outcome: **the CLI and every scanner remain MIT forever.** Open-core, if pursued, would add hosted scanning, team dashboards with RBAC, SLA support — never relicense existing code.

- **2028 — execute.** Whichever path the 2027 gate chose, scale it. Pure-OSS path: consider donation to a foundation (OpenSSF). Open-core path: separate company repo, clean product/project boundary.

The plan defers open-core for at least 24 months because at single-maintainer scale and pre-PMF, splitting features into a paid tier fragments a community before it exists.

---

## 10. Compliance milestones

| Target | Window | Why |
|---|---|---|
| **EU CRA stance published** | Q2 2026 | Reporting obligations for the broader regulation apply Sept 11, 2026; `docs/security/cra-stance.md` declares mythos-agent's role (currently *not* an Open-Source Steward). |
| **OpenSSF Best Practices Badge — Passing** | Q3 2026 | Free, mostly self-cert; required ≤14-day vuln response; unlocks downstream enterprise adoption. |
| **OSPS Baseline L1 (Basic Hygiene)** | Q4 2026 | 40-control checklist aligned to EU CRA. Scorecard v6 produces machine-readable conformance evidence. |
| **OpenSSF Best Practices Badge — Silver** | end 2027 | Adds 1-year roadmap, governance doc, signed releases, 80% test coverage, dependency monitoring. |
| **OSPS Baseline L2 (Standardized)** | mid-2027 | Pre-condition for the Y2 sustainability decision gate. |
| **OpenSSF Gold + first third-party security audit** | end 2028 | CNCF Sandbox application prerequisite if a foundation path is later chosen. |

EU CRA full obligations apply Dec 11, 2027.

---

## 11. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | **Supply-chain compromise of mythos-agent itself** (Trivy was hit twice in 2025–2026) | Medium | Critical | All actions pinned to commit SHA, Sigstore release signing, npm provenance, SLSA L3 build provenance, 2FA mandatory, signed commits, reproducible builds, public threat model at `docs/security/threat-model.md`. |
| 2 | **Solo-maintainer burnout / bus-factor** (Gitleaks → Betterleaks; ZAP → Checkmarx) | High | Critical | Active recruiting in 2026; named successor in `MAINTAINERS.md`; explicit Phase 2/3 governance triggers; emeritus path documented. |
| 3 | **False-positive drift** | Medium | High | 500-vuln benchmark as regression gate; FP rate tracked per release in machine-readable JSON. |
| 4 | **Anthropic API dependency** (provider risk) | Medium | High | Ollama / vLLM / OpenAI paths kept equal-class in `src/agent/providers/`. |
| 5 | **Adversarial misuse** of an offensive-capable scanner | Medium | Medium | Responsible-use notice in `README.md`; ethics clause in `CONTRIBUTING.md`; defensive framing throughout marketing. |
| 6 | **CVE-disclosure overload** as adoption grows | Low (2026), High (2028) | Medium | Formalize `SECURITY.md` triage process now; dedicated security-triage maintainer role at TSC phase. |
| 7 | **tree-sitter grammar coverage gaps** | Medium | Medium | Pin grammar versions in `package.json`; test matrix per grammar; contribute upstream fixes. |
| 8 | **Competing project absorbs community** | Medium | High | Differentiate on autonomy and reasoning, not rule count; maintain velocity on knowledge graph and agent work. |
| 9 | **Trademark dispute over Mythos framing** | Low | Medium | Always *inspired by*, never parity claim; "Mythos-Agent" treated as a self-contained compound; affiliation disclaimer in `VISION.md` and `README.md`. |
| 10 | **Governance entanglement with a sponsor** (Gitleaks lesson) | Low | Critical | License firewall sentence in `GOVERNANCE.md`; trademark held personally until Phase 2; fiscal-host transfer requires consensus. |

---

## 12. How this roadmap evolves

- **Refresh cadence.** Annually. Material changes (themes added or dropped, governance triggers changed, sustainability gate criteria changed) require an [RFC](docs/rfcs/).
- **Active-plan cadence.** Every 6 months. Each new pinned Goals issue replaces the prior one and links forward.
- **Verification.** Before any roadmap PR merges: link check, path-existence check, governance consistency check, contributor dry-run, metric specificity scan. Procedure in [docs/rfcs/0001-roadmap-2026-2028.md](docs/rfcs/0001-roadmap-2026-2028.md) (the dogfood RFC).

---

*Last refreshed: April 2026. Next refresh: April 2027 (or sooner if an RFC ships).*
