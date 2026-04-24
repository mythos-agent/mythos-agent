# Outbound Disclosure Policy

**Adopted:** 2026-04-24.
**Status:** Load-bearing. Changes require a maintainer-signed-off PR. Retrospective changes to past-disclosure handling are not permitted.

## Why this exists

[`SECURITY.md`](../../SECURITY.md) covers **inbound** reports — how third parties disclose vulnerabilities in mythos-agent to us. This document covers the inverse: **outbound** — how the mythos-agent project handles vulnerabilities *it* discovers in other open-source projects.

It is pre-committed now, before the project has filed any outbound findings, precisely because adopting discipline *after* a finding gets exciting is hard. Adopting it now is cheap. That asymmetry is the whole point.

## Scope

This policy applies when mythos-agent maintainers, or a recognized contributor acting as a mythos-agent researcher (e.g., submitting a CVE Replay case, writing a Hunt-pipeline case study, publishing a blog post under the project's name), discover a previously-unknown vulnerability in another project.

It does **not** cover:

- Individual users pointing mythos-agent at their own code or code they're authorized to review — that's between the user and the affected project. `SECURITY.md` § Out of scope covers this.
- Vulnerabilities in mythos-agent dependencies — those follow the dependency-maintainer's own disclosure process.
- Already-disclosed, already-patched CVEs we replay in [`benchmarks/cve-replay/`](../../benchmarks/cve-replay/README.md) — those are public by definition.

## The five commitments

### 1. Never publish before patch + embargo

Finding → private report → default **90-day embargo**. Embargo starts when the maintainer acknowledges receipt, not when we send it.

- If the maintainer is unresponsive after 14 days, we re-send via a second channel (GitHub private vulnerability reporting, `security@` if listed) before considering the report escalated under § Escalation.
- Shorter embargoes are negotiable with the maintainer when (a) the vuln is being actively exploited, or (b) the maintainer requests it.
- Longer embargoes are honored up to **180 days total**. Beyond that, we coordinate with the maintainer on a forced-disclosure plan rather than holding indefinitely; holding a finding past 180 days erodes user safety without adding maintainer value.

### 2. Never publish PoC before the patch is available

The writeup, proof-of-concept, and exploit details wait until the fix has shipped to the ecosystem. "Shipped" means the patched version is published to the relevant registry (npm, PyPI, Maven Central, crates.io, Go proxy, etc.), not merely committed to main.

If we publish timing details or affected version ranges before the fix ships, we mark them as embargoed-for-verification and pull them if the maintainer asks.

### 3. Always credit maintainers

Every writeup attributes the fix to the maintainer by name (with their consent). We do not publish writeups that frame ourselves as having "saved" a project — maintainers chose to fix the bug; we reported it. The correct verb is "reported," not "rescued."

Declined credit — a maintainer requests anonymity, or asks us not to publish the case study at all — is always honored. Silence from the maintainer is not consent; if we cannot reach them after the embargo ends, we publish with a neutral "fix implemented upstream" framing and no attribution.

### 4. Always acknowledge our own false positives

If mythos-agent produced a finding that turned out to be a false positive during the investigation — even if a different real vuln was found in the same session — we document it in the writeup. No quiet corrections. This includes:

- Reporting the wrong root cause.
- Reporting the wrong file or line.
- Misunderstanding the maintainer's original fix.
- Hypothesis-based scans that produced the report on reasoning we later decide was wrong.

This is the commitment that separates security research from vulnerability marketing. A writeup that acknowledges its own errors is more persuasive than one that claims a clean narrative, and skeptical readers (r/netsec, HN, lobste.rs) are trained to notice the omission.

### 5. Preferred channel: Huntr.dev for npm / PyPI / supported OSS

When the target is an OSS library covered by [Huntr](https://huntr.com), Huntr is the default channel. It handles maintainer notification, CVE assignment via CNA, fix-release tracking, bounty payment, and embargo enforcement — which keeps the project off the critical path for disclosure ops and provides third-party validation via the Huntr leaderboard.

For targets not on Huntr: use the project's documented security channel. If none exists, fall back in order: maintainer's `security@` email if listed → GitHub private vulnerability reporting → direct DM to a maintainer with "security" in the subject. Do **not** open a public issue, PR, or Discussions thread as the first contact.

## Escalation: what breaks the policy

Policy breaks are permitted only for these triggers, and must be documented with the specific reason in the eventual writeup:

- **Actively-exploited vuln with no maintainer response.** After 14 days of attempted contact via multiple channels, we may publish a defensive advisory — affected version range and mitigation guidance only, no PoC — to protect users in the meantime.
- **Maintainer explicitly requests faster publication.**
- **Independent publication by a third party.** Once a vuln is public elsewhere, our embargo is moot; we publish our analysis.
- **Legal compulsion** (e.g., court order). If this ever happens, the writeup notes it without revealing sealed details.

## Record-keeping

Every outbound finding is logged in `docs/security/disclosures.md` (maintained private while embargoed, made public with the writeup) with:

- Date reported, date patch released, date public writeup.
- Target project, affected versions, CWE, severity.
- Maintainer contact method, response timeline.
- Whether any § Escalation section was invoked.
- Whether any § 4 own-false-positive acknowledgment was made.

This log is the paper trail a third party can audit to verify we've held to this policy. Without it, the commitments above are untestable claims.

## Pre-commitment rationale

Security-tool projects routinely violate these commitments during launch pressure. The reasons are predictable:

- "The finding is really cool, a fast publish will get us on HN" — violates § 1.
- "The PoC is the best part of the writeup, we'll redact it later" — violates § 2.
- "The maintainer didn't respond to our credit request, we'll assume it's fine" — violates § 3.
- "Acknowledging the false positive makes us look bad" — violates § 4.
- "Huntr would take too long, let's just email" — arguable on § 5, but often a rationalization for §§ 1–4.

Adopting these rules in writing, before the pressure exists, is the mechanism that makes them hold. Linking this document from [`SECURITY.md`](../../SECURITY.md) and [`README.md`](../../README.md) commits the project publicly — retracting or softening the commitments becomes a reviewable PR, which is the safeguard.

## See also

- [`SECURITY.md`](../../SECURITY.md) — inbound vulnerability reporting
- [`benchmarks/cve-replay/README.md`](../../benchmarks/cve-replay/README.md) — replaying already-disclosed CVEs; explicitly out of scope for this policy
- [`docs/security/threat-model.md`](threat-model.md) — mythos-agent's own threat model
- [`docs/bounty.md`](../bounty.md) — inbound scanner-rule contribution bounty (separate program)
