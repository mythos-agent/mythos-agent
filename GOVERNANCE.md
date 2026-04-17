# Project Governance

sphinx-agent is an open-source project maintained by volunteers. This document describes how decisions are made.

## Current Model: Benevolent Maintainer

Today, sphinx-agent has a single lead maintainer (see [MAINTAINERS.md](./MAINTAINERS.md)) who has final say on merges, releases, and roadmap direction. This keeps the project moving while the community grows.

As the contributor base grows, we will transition to a multi-maintainer model (see "Becoming a Maintainer" below).

## Decision-Making

Most decisions are made by **lazy consensus** on GitHub:

- Someone proposes a change (issue, discussion, or PR).
- If no one objects within a reasonable window (~3–7 days for non-trivial changes), the change is accepted.
- If there is disagreement, we discuss until consensus is reached.
- If consensus cannot be reached, the lead maintainer makes the final call.

### Change Classes

| Change type | Who can approve |
|---|---|
| Typo / docs fix | Any maintainer |
| Bug fix | Any maintainer |
| New feature / scanner rule | Any maintainer; RFC discussion encouraged for large features |
| Breaking change | Lead maintainer + 1 other maintainer (when multi-maintainer) |
| License change | Consensus of all maintainers + open discussion period (14 days minimum) |
| New maintainer | Existing maintainers by lazy consensus |

### Proposing a Significant Change

For anything beyond a bug fix or minor feature, open a **Discussion** first to gather feedback before writing code. This avoids wasted effort and builds shared context.

## Becoming a Maintainer

Maintainers are contributors who:

- Have landed **5+ non-trivial PRs** that were accepted without major rework
- Demonstrate good judgment in reviews and issue triage
- Participate constructively in discussions (including disagreements)
- Are trusted by existing maintainers

Existing maintainers nominate new maintainers via lazy consensus. Nomination can happen in a private maintainer channel or via public discussion.

Maintainers commit to:

- Reviewing PRs and issues in their area within ~1 week
- Helping with releases
- Upholding the [Code of Conduct](./CODE_OF_CONDUCT.md)

Maintainers who become inactive for 6+ months may be moved to "emeritus" status with their consent. This is not punitive — life happens.

## Code of Conduct

All project spaces (issues, PRs, discussions, chat) follow the [Code of Conduct](./CODE_OF_CONDUCT.md). Enforcement is handled by the current maintainers. Violations should be reported to **conduct@sphinx-agent.dev**.

## Trademark and Licensing

- Source code is licensed under [MIT](./LICENSE).
- Contributions are accepted under the project license (inbound = outbound); no CLA required.
- The "sphinx-agent" name and logo belong to the project and may be used for discussing, teaching, or extending the software. Commercial use of the name requires prior written permission.

## Amending This Document

Changes to governance follow the same lazy-consensus process as code, with an extended (14-day) discussion window for substantive changes.
