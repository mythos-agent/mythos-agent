# Scanner-Rule Bounty Program — DRAFT, INACTIVE

> **Status: DRAFTED. INACTIVE.**
>
> This program **activates** when **either** of these triggers fires:
>
> 1. The first corporate user reports a production deployment of sphinx-agent, **OR**
> 2. Recurring sponsorship via GitHub Sponsors + Open Collective reaches **$5,000 / month**.
>
> Until then: contributions are recognized through the [Sphinx Mythos Pioneers](pioneers.md) leaderboard (no cash). The scanner-SDK and rule-pack contribution paths described in [CONTRIBUTING.md](../CONTRIBUTING.md) are open today; the cash bounty layer is not.

## Why this is drafted-but-inactive

Per the [AI-OSS funding research](sustainability/funding.md), **zero major AI OSS projects bounty contributors** today; the only sustained per-issue bounty programs in adjacent spaces are in security tooling (Nuclei) where VC funding underwrites the pool. Launching cash bounties at single-maintainer scale, before there is a funded pool, would create either an unpaid-invoice problem (claims with no money to pay) or a maintainer-bottleneck problem (review queue slows under contributor pressure for paid work).

The right sequence — and the one this document encodes — is: **recognition first (no cost), bounties when funded.**

## What the program will pay (when active)

| Contribution | Bounty | Conditions |
|---|---|---|
| Accepted scanner rule (rule pack OR built-in) | $50 | Real CWE; passes true-positive + true-negative tests; merged or published |
| Accepted scanner module (new `src/scanner/*-scanner.ts` or `sphinx-scanner-*` package) | $200 | Tests included; CHANGELOG entry; ≥1 reviewer approval |
| Accepted vulnerability addition to the published benchmark with reproducible PoC | $500 | Conforms to benchmark schema; independently verifiable; CC-BY licensed |

These prices are calibrated against [Nuclei's Template Reward Program](https://projectdiscovery.io/blog/announcing-the-nuclei-templates-community-leaderboard-and-rewards), which has two years of empirical data on what works at this scale.

## What is **explicitly out of scope** (will never pay bounties)

- **Core engine code** — `src/agents/`, `src/agent/`, `src/analysis/`, `src/cli/`. The maintainer review bottleneck for core code makes per-PR cash incentives counterproductive (single-maintainer review of paid work creates an asymmetric-pressure failure mode that has wrecked smaller bounty programs in the past).
- **Documentation, translations, design.** These are valued contributions but harder to objectively grade for payment; recognition tier covers them.
- **Issue triage, code review.** Same reason.
- **Vulnerability reports against sphinx-agent itself.** That goes through [SECURITY.md](../SECURITY.md), which separately addresses bug bounty (currently no paid program).
- **Bots and AI-generated PRs that bypass the maintainer review intent.** Substantive AI-assisted PRs are welcome (and properly disclosed); spammy automated submissions for bounty harvesting are not.

## Workflow (when active)

Modeled on Nuclei's `/attempt` and `/claim` workflow:

1. **Maintainer labels an issue** with `💎 bounty` and the dollar amount (e.g., `bounty:$200`).
2. **Contributor comments `/attempt #<issue-number>`** to declare intent. The first attempt holds priority for 14 days.
3. **Contributor opens the PR.** Standard PR review per [CONTRIBUTING.md § Pull request guidelines](../CONTRIBUTING.md#pull-request-guidelines).
4. **On merge, contributor comments `/claim #<issue-number>`.** A maintainer verifies and triggers payout.
5. **Payout.** Funds disburse from Open Collective to the contributor's payout method. Tax handling is the contributor's responsibility; Open Collective issues whatever receipt is required by the contributor's jurisdiction.

If a 14-day attempt window lapses without a draft PR, the attempt expires and a new contributor may claim.

## Funding source

The bounty pool is funded **exclusively** from Open Collective inflows tagged for "scanner-rule bounties" (or equivalent). It is **not** funded from:

- The maintainer's personal GitHub Sponsors income (which goes to maintainer time)
- Foundation grants earmarked for security audits (OSTIF, etc.)
- Sovereign Tech Fund or NLnet grants earmarked for specific deliverables

This separation keeps the bounty pool's accounting honest and means the program can transparently pause if inflows stop.

## Pause and resume

If the bounty pool runs dry (less than 1 month's expected payouts), the program automatically pauses:

1. New `💎 bounty` labels are not added until the pool is replenished
2. Existing labeled issues remain labeled; in-flight `/attempt` claims have 30 days to ship
3. A "PAUSED" banner is posted to this document and to the pinned `[Roadmap]` issue

Resumption requires the pool to reach 3 months' expected payouts. This buffer prevents thrash.

## Recognition is independent

A contributor who claims a bounty also gets full recognition under the [Sphinx Mythos Pioneers](pioneers.md) program. Cash and recognition are **additive**, not exclusive — taking the bounty does not remove your name from the leaderboard or change your tier.

A contributor may also **decline** a bounty (in their PR description: "no bounty, please") and receive only the recognition. Maintainers do not push contributors to accept payment; the program exists for those who want or need the cash.

## Conflict-of-interest rules (when active)

- Maintainers may **not** earn bounties on `💎 bounty` issues they labeled
- Maintainers may earn bounties on issues labeled by other maintainers (after Phase 2)
- Vendor employees who hold conflicts of interest per [MAINTAINERS.md](../MAINTAINERS.md) declare them publicly when claiming a bounty
- The lead maintainer publishes annual aggregate statistics (number of bounties paid, total amount, contributor count) at `docs/bounty-stats.md`

## Activation history

| Date | Event |
|---|---|
| 2026-04-18 | Program drafted; status INACTIVE pending trigger event. |

Future entries logged here when the program activates, pauses, resumes, or its terms change. Material changes to terms require an [RFC](rfcs/README.md).

## References

- [Nuclei Templates Reward Program](https://projectdiscovery.io/blog/announcing-the-nuclei-templates-community-leaderboard-and-rewards) — primary model
- [ProjectDiscovery OSS Bounty Program](https://projectdiscovery.io/blog/announcing-the-projectdiscovery-oss-bounty-program) — adjacent model with broader scope
- [Sphinx Mythos Pioneers](pioneers.md) — the recognition layer this program sits on top of
- [Funding stack](sustainability/funding.md) — where the pool's money comes from
