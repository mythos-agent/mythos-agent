# Funding shedu

> Working document. Tracks the sustainability stack and grant applications. Live status updated as funders respond.
> **Last reviewed:** 2026-04-18.

## Why this document exists

The Tidelift 2024 State of the Open Source Maintainer Report found that 60% of OSS maintainers have considered quitting; paid maintainers do 55% more security work. For a *security* OSS project, sustainable funding is a security control.

shedu's funding stack is intentionally incremental. We do not raise venture capital. We do not gate features. We accept money to extend the maintainer's time, fund security audits, fund a contributor bounty pool, and reduce bus-factor risk.

## The plan, in priority order

| # | Channel | Status | Target | Maintainer action |
|---|---|---|---|---|
| 1 | **GitHub Sponsors** (individual) | Pending | Q2 2026 | Create sponsors profile; uncomment in [`.github/FUNDING.yml`](../../.github/FUNDING.yml) |
| 2 | **Open Collective** (project, fiscal-hosted) | Pending | Q2 2026 | Apply via [Open Source Collective](https://opencollective.com/opensource) fiscal host |
| 3 | **Sovereign Tech Fund (STF)** application | Pending | Submit Q2–Q3 2026 | Prepare application using outline below |
| 4 | **NLnet NGI Zero** application | Pending | Submit Q2 2026 (next call) | Prepare proposal aligned to NGI Zero Core or Entrust track |
| 5 | **OSTIF** security audit grant | Plan | After OpenSSF Silver (target end-2027) | OSTIF requires Silver-tier badge or equivalent maturity |
| 6 | **OpenSSF sponsored project** | Plan | Phase 2 governance (≥3 active maintainers) | Apply once contributor count justifies it |
| 7 | **Foundation donation** (CNCF / OpenSSF / Linux Foundation) | Far horizon | 2028+ | Conditional on the Y2 sustainability decision gate |

We deliberately do **not** plan to:
- Raise VC funding (would shift identity from public good to startup)
- Gate features in the OSS edition
- Add a CLA (DCO sign-off is sufficient)

## Channel briefs

### 1. GitHub Sponsors

- Personal account first (the existing recommended pattern at single-maintainer scale; vLLM, Aider, Pydantic AI all do this)
- One-off and monthly tiers; no perks-as-features
- Tip jar framing — the maintainer keeps their day job until recurring revenue ≥ 80% of salary for 6 months (Henry Zhu / Babel pattern)
- Funds flow directly to the maintainer; tax handling is the maintainer's responsibility

### 2. Open Collective

- Project-level account, fiscal-hosted by [Open Source Collective](https://opencollective.com/opensource)
- Funds flow to the OSC nonprofit, which disburses on the project's behalf with full accounting transparency
- Use case: bounty pool funding (so payouts run through a 501(c)(6), not the maintainer personally)
- Use case: receiving corporate sponsorship that needs an invoice + a tax-deductible receipt (which an individual maintainer cannot issue)

### 3. Sovereign Tech Fund (Germany)

[STF](https://www.sovereigntechfund.de) funds security-relevant open-source infrastructure. Past grantees include curl, OpenSSL, GnuPG. They explicitly fund OSS maintenance, security audits, and "contractor" work to advance specific deliverables.

**Application outline for shedu's STF application:**

- **Project relevance to digital sovereignty.** shedu is one of very few open-source AI security agents with multi-provider local-model support (Ollama / vLLM); it directly reduces EU dependence on closed-source US scanners (Snyk, Semgrep Cloud, Anthropic's proprietary Mythos).
- **Concrete deliverables to fund.** (a) deterministic taint engine v1 (the work in `src/analysis/taint-engine.ts`); (b) 500-vuln benchmark dataset; (c) third-party security audit; (d) contributor bounty pool seed for scanner rules. Each is a line item with hours/cost estimate.
- **Maintenance model.** Public RFC process, multi-phase governance plan, OpenSSF Best Practices Badge progression — already documented in repo, link directly.
- **Timeline.** 12-month engagement; quarterly reporting against the H1/H2 Goals issues.
- **Counterpart commitment.** Maintainer dedicates X hours/week; recurring funding from other channels covers the gap.

### 4. NLnet NGI Zero

[NLnet's NGI Zero](https://nlnet.nl/) calls fund OSS aligned with the EU's Next Generation Internet program. Two relevant tracks:

- **NGI Zero Core** — internet-architecture tooling
- **NGI Zero Entrust** — privacy and trust enhancing technologies (PETs)

**Application angle:** shedu's AI-misuse risk scanning differentiation (prompt-injection sinks, unsafe LangChain patterns, MCP-server misconfig, exposed model weights) directly addresses the NGI Entrust trust-enhancement remit. Funded grants typically run €5,000–€50,000 per milestone.

Submit during the [next NGI Zero call](https://nlnet.nl/news/) (calls usually run April / June / October).

### 5. OSTIF security audit grant

[OSTIF](https://ostif.org/) coordinates and funds third-party security audits for OSS. Past audits: bcrypt, Python crypto libs, OpenVPN, libssh.

**When to apply:** after shedu reaches OpenSSF Silver tier (planned end of 2027). OSTIF expects projects to have working CI, signed releases, and an active maintainer team — Silver-tier criteria align well.

**What an OSTIF-funded audit produces:** public report of findings, fix coordination with maintainers, follow-up confirmation. Audited code earns durable credibility with downstream Manufacturers.

### 6. OpenSSF sponsored project

[OpenSSF](https://openssf.org/) sponsors selected OSS security projects with maintainer time, infrastructure, and audit coverage. Application requires:

- ≥3 active maintainers
- OpenSSF Best Practices Passing badge (planned Q3 2026)
- A clear roadmap and demonstrated production adoption

Apply when Phase 2 governance is reached (≥3 active maintainers).

### 7. Foundation donation (CNCF / OpenSSF / Linux Foundation)

A "donation" to a foundation transfers trademark, IP, and governance to the foundation in exchange for vendor neutrality, infrastructure, and brand credibility.

This is a 2028+ decision — and only one of two paths the [Y2 sustainability decision gate in ROADMAP § 9](../../ROADMAP.md#9-sustainability--commercial-posture) can produce. The other path is open-core via a separate company. Both leave the CLI and all scanners MIT in perpetuity.

## Reporting and transparency

Every funder gets:

- Quarterly progress against the pinned `[Roadmap]` Goals issue
- Annual financial transparency report (Open Collective provides this automatically; GitHub Sponsors income is reported in aggregate by the maintainer)
- Public attribution at `docs/sponsors.md` (lands once first sponsor signs)

## Bus-factor and continuity

Funding does not solve bus-factor on its own (Filippo Valsorda makes this point well in [Geomys: A Sustainable OSS Maintenance Firm](https://words.filippo.io/geomys/)). The sustainability stack pairs with the [governance evolution](../../GOVERNANCE.md#governance-evolution) plan: as funding grows, additional maintainers come into Phase 2 and onward. Money without humans is not sustainable.

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication. |
