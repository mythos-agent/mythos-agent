# mythos-agent and the EU Cyber Resilience Act

> **Status (April 2026):** mythos-agent is **not an Open-Source Steward** under the CRA. This document explains what that means for you.
>
> **Last reviewed:** April 18, 2026.
> **Next scheduled review:** September 2026 (before CRA reporting obligations apply).

## Background

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) entered into force on December 10, 2024.

- **Vulnerability and incident reporting obligations** apply from **September 11, 2026**.
- **Full obligations** (CE marking, conformity assessment, technical documentation, security update commitments) apply from **December 11, 2027**.

The CRA defines three relevant roles:

| Role | Who | Obligations |
|---|---|---|
| **Manufacturer** | Anyone who places a product with digital elements on the EU market commercially | Full CRA obligations: SBOM, CE marking, conformity assessment, 24-hour early warning + 72-hour full report on actively-exploited vulnerabilities, security updates for the product's expected lifetime |
| **Open-Source Steward** | A legal entity that provides sustained support for free and open-source software used commercially in EU products | Lighter obligations: publish a cybersecurity policy, run coordinated vulnerability disclosure (CVD), report actively-exploited vulnerabilities, cooperate with EU market surveillance |
| **Hobbyist / non-monetized maintainer** | An individual or informal group not commercially distributing the software | **No CRA obligations**. Donations and sponsorship that reimburse costs do not change this status. |

## mythos-agent's role today

mythos-agent is currently:

- Maintained by an unpaid individual contributor (the lead maintainer).
- Distributed under MIT via npm and GitHub.
- Not placed on the EU market commercially by any legal entity associated with the project.
- Not part of a legal entity that provides "sustained support."

**Therefore mythos-agent's lead maintainer is a hobbyist / non-monetized maintainer under the CRA**, with no CRA obligations attaching to the project itself.

## What this means for you (as a downstream user)

### If you are an individual or non-commercial user

The CRA does not apply to you when you use mythos-agent. Use the project as you would any MIT-licensed tool.

### If you are a commercial entity using mythos-agent in a product placed on the EU market

**You are the Manufacturer of the product.** Full CRA obligations attach to your product, including the parts that incorporate or depend on mythos-agent. You retain responsibility for:

- SBOM coverage that includes mythos-agent and its dependencies
- Vulnerability monitoring of mythos-agent
- Security updates of mythos-agent in your product (including back-porting fixes if your release lifecycle differs from mythos-agent's)
- Coordinated vulnerability disclosure for issues affecting your product

To make this practical, mythos-agent provides:

- A **CycloneDX SBOM per release** (lands in H1 2026 supply-chain hardening session)
- **Sigstore-signed releases** with cosign verification (lands in H1 2026)
- **npm provenance attestations** (lands in H1 2026)
- A **published vulnerability disclosure process** ([SECURITY.md](../../SECURITY.md))
- A **public threat model** at [`docs/security/threat-model.md`](threat-model.md) (lands in H1 2026)
- **EOL dates published in advance** ([RELEASES.md](../../RELEASES.md))

These are voluntary contributions to make mythos-agent practically usable in CRA-compliant downstream products. They are not legally-required obligations of the mythos-agent maintainer under the CRA.

### If you are a commercial entity that wants mythos-agent to take on Open-Source Steward obligations

This requires a legal entity to provide sustained support. The lead maintainer is open to discussing fiscal-host arrangements (e.g., Open Source Collective, Sovereign Tech Fund support) that would make this feasible. Contact security@mythos-agent.com to start that conversation.

## When this stance might change

The maintainer's status may change if any of these occur:

- A legal entity (company, foundation, fiscal host) takes on sustained support of mythos-agent.
- The lead maintainer begins commercial distribution of mythos-agent (e.g., a paid hosted service or commercial-license tier).
- The lead maintainer accepts paid maintenance work that exceeds cost-reimbursement (per the OpenSSF / EC guidance, sustained paid maintenance can shift status from hobbyist to steward).

Any change to the CRA stance will be:

1. Announced in the next release's CHANGELOG
2. Reflected in this document with a dated entry
3. If shifting *toward* Steward status: published as an [RFC](../rfcs/) for community input before taking effect

## Cooperation with EU market surveillance

Even though the CRA does not currently impose obligations on the maintainer, mythos-agent voluntarily commits to:

- **Cooperate in good faith** with any reasonable inquiry from EU national market-surveillance authorities (BSI, ANSSI, ENISA, etc.).
- **Notify the community** of any actively-exploited vulnerability via a GitHub Security Advisory, the CHANGELOG, and (if severe) a notice in [Discussions](https://github.com/mythos-agent/mythos-agent/discussions).
- **Not impede downstream Manufacturers' compliance** by withholding SBOM, version, or fix-status information.

## References

- [Regulation (EU) 2024/2847 — Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [European Commission — CRA portal](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [European Commission — CRA and Open Source](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source)
- [OpenSSF — CRA Brief Guide for OSS Developers](https://best.openssf.org/CRA-Brief-Guide-for-OSS-Developers.html)
- [OpenSSF — OSS and the CRA: Manufacturer or Steward?](https://openssf.org/blog/2025/06/02/oss-and-the-cra-am-i-a-manufacturer-or-a-steward/)

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication; declares hobbyist/non-monetized status. |
