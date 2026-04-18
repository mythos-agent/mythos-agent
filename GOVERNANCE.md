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

## Governance Evolution

The governance model adapts as the project grows. Transitions are driven by **triggers**, not dates.

### Phase 1 — Benevolent Maintainer (current)

- Solo lead per [MAINTAINERS.md](./MAINTAINERS.md)
- Lazy consensus on issues / PRs / Discussions
- Final call on disagreement: lead maintainer
- Valid while active maintainers count is < 3

### Phase 2 — Multi-Maintainer (trigger: 3+ active maintainers)

- Maintainers specialize by area (scanner / analysis / CLI / agents — matched to MAINTAINERS.md columns)
- Lazy consensus continues; in-area decisions belong to the area maintainer
- Cross-area decisions follow the existing 3–7 day window
- Lead maintainer remains the tiebreaker; emeritus path opens
- New CODEOWNERS structure reflects the area split

### Phase 3 — Technical Steering Committee (trigger: 5+ active maintainers OR commercial posture declared)

- TSC of 3–5 seats. Minimum allocation: ≥1 lead, ≥1 analysis-area, ≥1 scanner-area; remaining seats by lazy consensus of all active maintainers
- TSC scope: roadmap direction, breaking changes, license posture, commercial-gate decisions, conflict resolution
- Quarterly meeting notes published in `docs/tsc-meetings/`
- TSC **cannot** unilaterally relicense the core; the existing 14-day consensus window plus the License Firewall (above) still bind
- Public TSC nomination process: any active maintainer or any contributor with 10+ merged non-trivial PRs may nominate

### Trademark and Project Identity

- The `sphinx-agent` name and logo are currently held by the lead maintainer personally
- A future transfer to a fiscal host (e.g., Open Source Collective) is on the table once Phase 2 is reached
- Until then, commercial use of the name requires prior written permission from the lead maintainer
- A trademark dispute or attempted brand capture by a sponsor is automatic grounds for an emergency RFC under the same 14-day consensus rule as a license change

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

## Security and Supply Chain

sphinx-agent is a security tool. A compromise of this project would propagate harm to every downstream user at the speed of CI. We therefore hold the project to baseline security standards that apply to all maintainers, regardless of governance phase.

### Account security (mandatory)

- **Two-factor authentication is mandatory** on the GitHub account of every maintainer and on the npm publish account. Hardware-key (FIDO2 / WebAuthn) is preferred; SMS is not acceptable.
- **No shared credentials.** The npm publish token, signing identities, and any service tokens are scoped to a single human or to an automated workflow with explicit identity (OIDC), never to a shared account.
- **Recovery contact** for the GitHub organization and the npm package is documented in a private note held by the lead maintainer; rotation cadence: annually.

### Repository protections (mandatory)

- `main` and `release/*` branches are protected: required PR review, required passing checks, no force-push, no direct push.
- All `.github/workflows/*` changes require explicit lead-maintainer review (CODEOWNERS-enforced).
- All `package.json`, `package-lock.json`, and `release-please-config.json` changes require explicit lead-maintainer review.

### Build and release integrity (mandatory)

- Releases are produced exclusively from CI, never from a developer machine.
- All third-party GitHub Actions are pinned to a commit SHA, not a moving tag. Pinning is automated via [`frizbee`](https://github.com/stacklok/frizbee) or [`pin-github-action`](https://github.com/mheap/pin-github-action); SHA updates are reviewed via Dependabot PRs.
- Release artifacts (npm tarball, SBOM) are signed with cosign keyless OIDC. See [`.github/workflows/sigstore-release.yml`](.github/workflows/sigstore-release.yml) and [`.github/workflows/sbom.yml`](.github/workflows/sbom.yml).
- npm publish uses provenance attestations (`--provenance`).
- SLSA Level 3 build provenance is generated per release via `actions/attest-build-provenance`.

### Threat model

The full public threat model lives at [`docs/security/threat-model.md`](docs/security/threat-model.md). It is reviewed annually and whenever a new attack class enters scope (new agent provider, new MCP server capability, new contributed scanner that touches the network).

### Vulnerability response

Vulnerability handling, SLAs, and the EU Cyber Resilience Act stance live in:

- [`SECURITY.md`](SECURITY.md) — disclosure process and SLAs
- [`docs/security/cra-stance.md`](docs/security/cra-stance.md) — CRA role declaration
- [`docs/security/sbom.md`](docs/security/sbom.md) — SBOM policy

### Conflict of interest disclosure (for maintainers)

Maintainers who work for, consult for, or hold equity in a vendor that competes with or sells alongside sphinx-agent must disclose that relationship in their MAINTAINERS.md entry. Disclosure does not disqualify; non-disclosure is a removal-eligible offense.

### License firewall

The CLI, every scanner, every analysis module, and every prompt is MIT-licensed and **will remain MIT in perpetuity.** Any future commercial differentiation will come from new code contributed under a separate license, never from relicensing existing OSS code. This commitment requires a unanimous vote of all active maintainers and a 14-day public discussion period to change — the same process as a license change of the project itself.

This sentence exists to prevent an Opengrep-style fork. If a sponsor, employer, or future steward seeks to change it, every maintainer is empowered to publicly object.

## Amending This Document

Changes to governance follow the same lazy-consensus process as code, with an extended (14-day) discussion window for substantive changes.
