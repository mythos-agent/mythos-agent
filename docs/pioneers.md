# 🦁 Mythos-Agent Pioneers

> Recognition for the people building mythos-agent. This page is auto-updated by [`.github/workflows/pioneers.yml`](../.github/workflows/pioneers.yml) at the start of every month from contributor stats.
>
> Last updated: _waiting for first auto-run_

## What it is

The **Mythos-Agent Pioneers** is a recognition tier (no cash) for the people who land code, scanners, tests, docs, and integrations in mythos-agent. It exists because contributing to OSS is unpaid by default and that is unfair: the least we can do is name the people doing the work, in public, in a place adopters and recruiters will see.

A separate, currently **inactive** scanner-rule cash bounty program is drafted at [`docs/bounty.md`](bounty.md) and activates upon a defined trigger event.

## Tiers

| Tier | Threshold | Recognition |
|---|---|---|
| **Founding Pioneer** | First 10 external contributors with a merged non-trivial PR | Permanent listing in this page; profile card in next release notes; opt-in conference invite list |
| **Core Pioneer** | 5+ merged non-trivial PRs across any category | Profile card in this page; profile card in release notes; opt-in conference invite list |
| **Active Pioneer** | 1+ merged non-trivial PR in the last 90 days | Listed in this page under "Active Pioneers" |
| **Emeritus Pioneer** | Was a Core Pioneer; inactive for 12+ months | Listed under "Emeritus" — credit retained, not displayed in active section |

"Non-trivial" excludes typo fixes, single-character changes, dependency-bot PRs, and revert-only PRs. The auto-update workflow uses heuristics (lines added + reviewer-attested label) so judgment cases land in the maintainer's review.

## Categories

A Pioneer's profile card includes their primary category (heuristic from where their merged PRs landed):

| Icon | Category | What it means |
|---|---|---|
| 🛡 | Scanner | Built or improved scanners under `src/scanner/` |
| 🔍 | Analysis | Worked on `src/analysis/` (taint, call graph, parser, knowledge graph) |
| 🤖 | Agent | Worked on `src/agents/`, `src/agent/` (orchestrator, providers, prompts, fix-validator) |
| ⌨️ | CLI | Worked on `src/cli/`, `src/server/`, `src/mcp/` |
| 🧪 | Test | Substantially expanded test coverage |
| 📚 | Docs | Substantially expanded documentation |
| 🔌 | Integration | Wrapped a new external tool in `src/tools/` |
| 🦁 | Polymath | Multiple categories |

A Pioneer can earn multiple category badges over time.

## Founding Pioneers (first 10 external contributors)

_None yet — be the first!_

When you are one of the first ten external contributors with a merged non-trivial PR, you appear here permanently with your GitHub avatar, profile name, your area badge, and the PR that earned you the entry.

## Core Pioneers

_None yet — earn your way in by landing 5+ merged non-trivial PRs._

## Active Pioneers (last 90 days)

_Auto-updated. Empty between auto-runs._

## Emeritus Pioneers

_None yet._

Pioneers who become inactive for 12+ months are moved here with their consent. Like maintainers, this is honorary. Returning to the active list is just a matter of resuming engagement.

---

## Conference invite list

Pioneers may opt in to receive an invitation when mythos-agent is presented at a conference (DEF CON AI Village, Black Hat Arsenal, USENIX Security WOOT, academic workshops). The invite covers a co-presenter slot for any Pioneer whose work is being demoed.

To opt in, comment on a tracking issue (link to be added) or email conduct@sphinx-agent.dev. Opting out at any time is one email.

## How to claim corrections

If the auto-updater missed you, mis-categorized you, or the wrong avatar shows up, open a Discussion with the `pioneers-correction` label or email conduct@sphinx-agent.dev. Corrections land in the next monthly run.

## Privacy

The auto-updater uses **only public GitHub data** — your username, avatar, and the metadata of merged PRs. It does not pull email, location, or any private profile field. If you'd like to be excluded from this page entirely, email conduct@sphinx-agent.dev — your contribution stands; the listing is opt-out-able.
