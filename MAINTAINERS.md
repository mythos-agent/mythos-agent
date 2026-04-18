# Maintainers

This file lists the active maintainers of shedu. Maintainer responsibilities, the path to becoming one, and the multi-phase governance evolution are described in [GOVERNANCE.md](./GOVERNANCE.md).

## Active Maintainers

| Name | GitHub | Areas | Conflicts of interest | Contact |
|---|---|---|---|---|
| Zhijie Wong | [@zhijiewong](https://github.com/zhijiewong) | Lead · scanner · analysis · CLI · agents (currently all areas — Phase 1) | None declared | conduct@sphinx-agent.dev |

**Areas legend** (used when Phase 2 begins):

- **Lead** — final tiebreaker, holds trademark/release keys, owns governance amendments
- **Scanner** — `src/scanner/`, `src/rules/`, `src/tools/`, scanner SDK
- **Analysis** — `src/analysis/` (taint, call graph, parser, knowledge graph)
- **Agents** — `src/agents/`, `src/agent/` (orchestrator, providers, prompts, fix-validator)
- **CLI** — `src/cli/`, `src/server/`, `src/mcp/`, user-facing UX

A maintainer can hold multiple areas. The `Lead` role is held by exactly one person at a time.

## Continuity Contacts

For continuity if a primary contact becomes unreachable. Listed in the order they should be tried.

| Function | Primary | Successor |
|---|---|---|
| **SECURITY** (vulnerability disclosure) | Zhijie Wong (security@sphinx-agent.dev) | _Pending — to be named when Phase 2 begins_ |
| **CONDUCT** (Code of Conduct enforcement) | Zhijie Wong (conduct@sphinx-agent.dev) | _Pending — to be named when Phase 2 begins_ |
| **RELEASES** (npm publish, signing) | Zhijie Wong | _Pending — to be named when Phase 2 begins_ |
| **TRADEMARK / DOMAIN** (sphinx-agent.dev, npm package owner) | Zhijie Wong (personally held) | _Transfer to fiscal host planned for Phase 2_ |

If you are reading this in an emergency and the primary contact is unreachable for 7+ days, escalate publicly via:

1. Open a [GitHub Discussion](https://github.com/zhijiewong/shedu/discussions) titled `[CONTINUITY]` describing the situation
2. If there are active maintainers besides the primary, they may activate the trademark/release keys per the trademark-transfer clause in GOVERNANCE.md

## Emeritus Maintainers

_No emeritus maintainers yet._

Maintainers who become inactive for 6+ months may be moved to emeritus status with their consent (per [GOVERNANCE.md § Becoming a Maintainer](./GOVERNANCE.md#becoming-a-maintainer)). Emeritus is honorary, not punitive — it acknowledges past contribution while making the active list a true reflection of who is reachable now.

Emeritus maintainers retain:
- Listing in this file under the Emeritus section
- Credit in release notes for their historical contributions
- An open invitation to return to active status by resuming engagement

Emeritus maintainers do **not** retain:
- Merge rights on the repository
- Release-signing authority
- Voting rights in governance decisions

## How to Reach Maintainers

| Topic | Channel |
|---|---|
| Public questions, design discussions | [GitHub Discussions](https://github.com/zhijiewong/shedu/discussions) |
| Bug reports, feature requests | [GitHub Issues](https://github.com/zhijiewong/shedu/issues) |
| Security vulnerabilities | security@sphinx-agent.dev (see [SECURITY.md](./SECURITY.md)) |
| Code of Conduct concerns | conduct@sphinx-agent.dev |
| Trademark / commercial use of name | Lead maintainer (via security@ for now) |
| Sponsorship / fiscal-host inquiries | conduct@sphinx-agent.dev |

## Conflict-of-Interest Declarations

Each maintainer is expected to disclose any employment, consulting, or equity relationship with vendors that compete with or sell alongside shedu (see [GOVERNANCE.md § Security and Supply Chain — Conflict of interest disclosure](./GOVERNANCE.md#conflict-of-interest-disclosure-for-maintainers)).

Disclosures are listed in the "Conflicts of interest" column of the Active Maintainers table above. Updates to a disclosure go via PR, ideally with a co-signed acknowledgement from another maintainer when one exists.

## Document History

| Date | Change |
|---|---|
| 2026-04-18 | Add area columns, continuity contacts, conflict-of-interest column, emeritus rights/responsibilities. |
