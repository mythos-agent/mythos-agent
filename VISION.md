# Vision

> *shedu is the **Shedu**: an open-source autonomous security research agent. The reasoning depth of a senior pentester, the reach of a scanner, the licensing of a public good.*

**Shedu** is a self-contained name. *Sphinx* and *mythos* are both ancient Greek words meaning *legend* or *story*. The compound describes the project's own arc — a code-reading creature that hunts vulnerabilities the way Theban myth hunted travelers' wits. It is *inspired by* the same research direction as Anthropic's proprietary Mythos security agent, but it is not a clone, not affiliated, and makes no claim of feature parity.[^1]

## What shedu aims to be

A user running `shedu hunt` against their codebase should experience the project differently each year:

- **Today (2026).** Run a fast scan that combines pattern matching with AI reasoning. Get findings with reproducible evidence, ranked by exploitability, with optional auto-generated patches. Understand *why* a finding matters, not just *that* it exists.
- **Tomorrow (2027).** Ask shedu to *hunt* — to spend ten minutes investigating your repo for a vulnerability class, report what it explored, cite the code locations it considered, and surface findings a single-pass scanner would never reach.
- **The day after (2028).** Hand shedu a polyglot monorepo with twelve services. It maps trust boundaries, finds an attack chain spanning three service boundaries, generates a patch, generates a regression test, runs both, and reports the result.

These are capability arcs, not dated commitments. Stages advance when the work is ready; never before.

## Capability arcs

| Arc | What a user can do | Status |
|---|---|---|
| **Foundation & Depth** | Deterministic taint and call graphs feeding AI reasoning; <10% FP rate on a 500-vuln benchmark; full CWE Top 25 coverage. | In progress through H2 2026 |
| **Autonomy & Discovery** | Persistent codebase knowledge graph; multi-turn agent with backtracking; chain engine; novel-vuln benchmark; first community-credited CVEs. | Experimental flag work 2026, stabilizing 2027 |
| **Ecosystem & Scale** | Cross-service / monorepo / trust-boundary analysis; validated remediation pipeline; scanner-plugin community; research partnerships. | 2027–2028 horizon |

## What shedu will not become

These non-goals are stable. They change only via [RFC](docs/rfcs/).

- **Not a Semgrep replacement.** shedu integrates Semgrep; it does not duplicate rule-matching as its primary value.
- **Not a developer platform.** No project management, no IDE features beyond a thin MCP wrapper, no code-completion copilot.
- **Not a runtime security tool.** No EDR, no eBPF, no syscall monitoring. Static analysis plus bounded DAST only.
- **Not a compliance-only tool.** SOC2 / HIPAA / PCI / GDPR mappings are reporting layers, never the product.
- **Not a pentest-as-a-service replacement.** Augmentation for human researchers, not substitute.
- **Not closed-source at any layer.** The CLI and every scanner are MIT in perpetuity. Any future commercial differentiation comes from new code under a separate license, never from relicensing existing OSS.

## Where the strategic detail lives

- **[ROADMAP.md](ROADMAP.md)** — the multi-year strategic frame: themes, governance evolution, sustainability posture, OpenSSF compliance, EU CRA stance, risk register.
- **Pinned GitHub Issue `[Roadmap] shedu H1 2026 Goals`** — the active 6-month working plan. Items are claimable; markers indicate where help is wanted.
- **[GOVERNANCE.md](GOVERNANCE.md)** — how decisions get made and how that evolves as the project grows.

[^1]: *Mythos* is also the codename of Anthropic's internal security agent referenced in public Project Glasswing materials. shedu is an independent open-source effort, not affiliated with or endorsed by Anthropic. The Shedu identity is offered as a self-contained tagline; remove the comparison whenever you are not explicitly framing the research lineage.
