# mythos-agent RFCs

Substantive changes to mythos-agent — anything that affects more than one area, alters a public CLI / API surface, changes governance, or shifts the strategic direction in [VISION.md](../../VISION.md) or [ROADMAP.md](../../ROADMAP.md) — are proposed here as RFCs.

## When an RFC is required

| Change type | RFC required? |
|---|---|
| New scanner phase | **Yes** |
| Breaking CLI change | **Yes** |
| Governance change | **Yes** |
| New AI provider integration | **Yes** |
| Scanner plugin SDK contract change | **Yes** |
| License-related decision | **Yes** (also requires the [GOVERNANCE.md](../../GOVERNANCE.md) 14-day window) |
| New strategic theme in ROADMAP.md | **Yes** |
| Adding a scanner rule | No (use a regular PR) |
| Adding a tool integration | No (use a regular PR) |
| Bug fix | No (use a regular PR) |
| Documentation fix | No |

When in doubt, open a [GitHub Discussion](https://github.com/mythos-agent/mythos-agent/discussions) and ask.

## Process

1. **Copy the template.** `cp docs/RFC-TEMPLATE.md docs/rfcs/NNNN-short-slug.md`. Use the next free number.
2. **Open a PR** titled `[RFC] <Title>`. Mark Status as `Draft` initially.
3. **Discussion window.** 14 days minimum for substantive changes (governance, license, breaking CLI, new scanner phase). 3–7 days for non-trivial but bounded changes (per [GOVERNANCE.md § Decision-Making](../../GOVERNANCE.md#decision-making)).
4. **Move to `Discussion`** once you've addressed initial review comments and the PR is ready for broader input.
5. **Maintainer call.** A maintainer (or the TSC, in Phase 3) marks the RFC `Accepted`, `Rejected`, or requests revision. Decisions follow lazy consensus; if consensus does not form, the lead maintainer (or TSC majority) decides and writes the rationale into the RFC.
6. **At acceptance:** the RFC author or a maintainer creates a `tracking-#NNNN` issue and links the relevant pinned `[Roadmap]` bucket. Implementation PRs reference both.
7. **At completion:** the tracking issue is closed and the RFC's status is updated to a closing date.

## Statuses

| Status | Meaning |
|---|---|
| `Draft` | Author still iterating; feedback welcome but not blocking |
| `Discussion` | Open for community input; review window running |
| `Accepted` | Approved; implementation can begin |
| `Rejected` | Closed without acceptance; rationale recorded in the RFC |
| `Superseded by #NNNN` | A later RFC replaces this one |
| `Withdrawn` | Author closed the RFC before a decision |

## Index

| # | Title | Status | Discussion |
|---|---|---|---|
| 0000 | RFC template | n/a | [docs/RFC-TEMPLATE.md](../RFC-TEMPLATE.md) |

(More entries land here as RFCs are filed.)

## Why an RFC process

Sphinx-agent is a security tool with a single maintainer today and an ambition to be sustainable across multiple maintainers tomorrow. An RFC process:

- **Forces alignment before code lands.** A 14-day discussion window costs much less than rewriting six weeks of work the maintainer disagrees with at review.
- **Creates an audit trail.** Future contributors can read why a design choice was made, not just what it was.
- **Distributes decision-making safely.** Once we are in Phase 2 / Phase 3 governance, the RFC process is how non-lead maintainers can drive a roadmap-level change.
- **Demonstrates good governance to OpenSSF / CNCF / EU CRA reviewers.** "Has a documented decision-making process for substantive changes" is a Silver-tier badge criterion.

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication. |
