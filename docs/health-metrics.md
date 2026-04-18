# Project Health Metrics

> What we measure, how we measure it, where the dashboard lives, how often it refreshes.
> **Last reviewed:** 2026-04-18.

## What we measure (CHAOSS Starter Project Health)

The metric set is the [CHAOSS Starter Project Health model](https://chaoss.community/kb-metric-model-starter-project-health/) — a small, opinionated set of signals that funders, contributors, and adopters all check. Resisting metric inflation is itself a discipline; we publish only what we believe predicts the project's actual health.

| Metric | What it measures | Why it matters | Target by end-2026 |
|---|---|---|---|
| **Release frequency** | Number of npm releases per quarter | Stale projects drift; active ones ship | ≥4 minor + ≥10 patch / quarter (best effort) |
| **Time to first response** | Median hours from issue / PR open to first maintainer comment | Unanswered first contact is the biggest churn driver per Tidelift 2024 | <72 h for issues, <48 h for PRs |
| **Active contributor count** | Unique authors with merged commits in rolling 90 days | Bus-factor signal; recruitment pipeline indicator | ≥5 (currently 1) |
| **Bus factor** | % of commits in rolling 90 days authored by the top contributor | Existential risk indicator. Critical at single-maintainer scale. | ≤80% (currently 100%) |
| **Time-to-merge for first-time contributors** | Median days from PR open to merge for users with no prior merged PR | The first contribution decides whether someone returns | ≤7 days |
| **Open issue / PR age (75th percentile)** | How long the slowest-moving quarter of issues / PRs has waited | Backlog rot signal | ≤90 days |
| **OpenSSF Scorecard score** | 0–10 from [scorecard.dev](https://scorecard.dev/) | Machine-readable security posture; aligns to OSPS Baseline | ≥7.0 |
| **OpenSSF Best Practices Badge tier** | Passing / Silver / Gold | Adopter-visible credibility ladder | Passing by Q3 2026 |

Two metrics that we **do not** publish:

- **GitHub stars.** Vanity, gamed, and weakly correlated with project health. We track them for the `[Roadmap]` issue but they are not a CHAOSS metric.
- **Lines of code.** Famously misleading; rewards bloat.

## Tooling

- **Augur** (Python, Postgres-backed) — maintained by CHAOSS. Selected for mythos-agent because it directly models the CHAOSS metric definitions and exports a stable JSON schema we can consume from in-repo dashboards.
- **OpenSSF Scorecard** — for the security score; runs as a GitHub Action and uploads results to scorecard.dev.

We considered **GrimoireLab** (more powerful, more setup) and rejected it for now — Augur covers the chosen metric set with substantially less operations cost. Re-evaluate if our metric set grows beyond the Starter model.

## Where the dashboard lives

- **Public read-only summary:** `STATS.md` in this repo (regenerated quarterly from Augur)
- **Live dashboard:** `https://stats.sphinx-agent.dev` (planned; lands once the domain is provisioned)
- **Machine-readable JSON:** `stats.json` at the dashboard URL, also committed quarterly to the repo for archival

The `mythos-agent stats` CLI command (already in `src/cli/commands/stats.ts`) is extended to read `stats.json` and render the same numbers in the terminal — so the metric set is observable by users locally without leaving the CLI.

## Refresh cadence

| Refresh | Cadence | Mechanism |
|---|---|---|
| OpenSSF Scorecard | On every push to `main` | GitHub Action |
| Augur metric refresh | Daily | Augur scheduled job |
| `STATS.md` regeneration | Quarterly | `chore(stats):` PR opened by automation |
| Dashboard summary update | Quarterly | Tied to STATS.md refresh |
| Annual deep-dive | Yearly (April) | Blog post + ROADMAP refresh consultation |

## Privacy and ethics

- All metrics use **public GitHub data** plus the OpenSSF Scorecard public output
- No private contributor data, no IP-address logging, no telemetry from the CLI by default
- The opt-in scan-count telemetry described in `docs/telemetry.md` (placeholder; lands later H1 2026) is tracked separately and is **not** a project health metric

## Accountability

If a metric stays red for two consecutive quarters, the next ROADMAP annual refresh **must** address why and what changes. This is the explicit feedback loop tying measurement to action — without it, metric publishing degenerates into theatre.

## Why these specific targets

| Target | Source |
|---|---|
| <72 h first response on issues | Tidelift 2024 maintainer survey: top correlate of contributor return |
| ≤80% top-contributor commit share | CHAOSS bus-factor heuristic for "moderate concentration risk" |
| ≤7 day first-time-contributor merge | Empirical research on OSS retention (ICSE 2022) — beyond 7 days return rates collapse |
| ≥7.0 Scorecard | OpenSSF Silver-tier soft prerequisite |

## What changes in Phase 2 / Phase 3 governance

- Bus factor target tightens to **≤60%** in Phase 2 and **≤40%** in Phase 3
- A "review concentration" metric (% of reviews by top reviewer) is added in Phase 2
- A "decision concentration" metric (% of decisions resolved by lead alone) is added in Phase 3 to surface TSC effectiveness

## References

- [CHAOSS Starter Project Health model](https://chaoss.community/kb-metric-model-starter-project-health/)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [Augur project](https://chaoss.github.io/augur/)
- [Tidelift 2024 State of the Open Source Maintainer Report](https://www.tidelift.com/open-source-maintainer-survey-2024)
- [GOVERNANCE.md § Governance Evolution](../GOVERNANCE.md#governance-evolution)

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication; baseline metrics not yet captured. |
