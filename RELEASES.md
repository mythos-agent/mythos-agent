# Release Policy

How mythos-agent versions, ships, and supports its releases.

## Versioning

mythos-agent follows [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html), driven by [Conventional Commits](https://www.conventionalcommits.org/) via [release-please](https://github.com/googleapis/release-please).

| Commit prefix | Version bump | Example |
|---|---|---|
| `fix:` | patch | `2.0.0` → `2.0.1` |
| `feat:` | minor | `2.0.0` → `2.1.0` |
| `feat!:` or `BREAKING CHANGE:` footer | major | `2.0.0` → `3.0.0` |
| `chore:`, `docs:`, `style:`, `test:`, `refactor:`, `ci:`, `perf:` | none (no release) | — |

The CHANGELOG is auto-generated and committed alongside each release.

## Release cadence

| Track | Cadence | Purpose |
|---|---|---|
| **Patch** | As needed, typically weekly | Bug fixes, security patches, dependency updates |
| **Minor** | ~Monthly (best effort) | New scanners, CLI commands, integrations, non-breaking improvements |
| **Major** | Annually at most, ideally less | Breaking changes; preceded by a deprecation cycle |

"Best effort" reflects single-maintainer reality. The cadence is a target, not a contract.

## Release branches

| Branch | Purpose |
|---|---|
| `main` | Active development. CI gating before any merge. |
| `release/2.x` | LTS branch for v2.x patch releases (created when v3.0 is in development) |
| `release/1.x` | Maintenance for v1.x security fixes only (until EOL) |

Patch releases are cut from the corresponding `release/X.x` branch. Critical security fixes are back-ported to all in-support branches.

## Long-term support (LTS)

The latest major version is **Active**. The previous major version receives **security fixes only** for at least 6 months after a new major ships. EOL dates are published in advance.

| Major | Phase | Status |
|---|---|---|
| **2.x** | Active | Default; receives all fixes |
| **1.x** | EOL announced | Security-only until 2026-10-16 (6 months after v2.0 release) |
| **0.x (pre-1.0)** | End of life | No fixes |

The schedule above is the default; actual EOL announcements are made in the CHANGELOG and pinned in [Discussions](https://github.com/mythos-agent/mythos-agent/discussions) when set.

## Deprecation policy

- **Deprecation announcement** in the CHANGELOG and the relevant CLI command's `--help` output
- **Minimum 6-month deprecation window** before removal (single CLI release cycle plus one)
- **Migration guide** published in `docs/migrations/` for non-trivial removals
- **Major-version bump** required for actual removal

If a deprecation window cannot be honored (security-driven removal, upstream API gone), the rationale is documented in the migration guide.

## Release artifacts

Every release publishes:

- **npm package** at [`mythos-agent`](https://www.npmjs.com/package/mythos-agent) — with provenance attestations (lands in H1 2026 supply-chain hardening)
- **GitHub Release** with attached assets:
  - CycloneDX SBOM (lands in H1 2026)
  - cosign signature + bundle (lands in H1 2026)
  - SLSA L3 build provenance attestation (lands in H1 2026)
  - Source tarball
- **Docker images** at `ghcr.io/mythos-agent/mythos-agent` and `docker.io/sphinxagent/mythos-agent`
- **CHANGELOG.md** entry summarizing the release

Verification instructions for cosign signatures and SLSA provenance will live at [`docs/security/verify-release.md`](docs/security/verify-release.md) once H1 2026 supply-chain work lands.

## Security release process

Security releases follow the same versioning and branch model but are prioritized:

1. Issue is reported via [SECURITY.md](SECURITY.md) channels.
2. Triage and fix happen on a private branch.
3. Pre-disclosure notification is sent to known production deployments (opt-in list at `docs/security/pre-disclosure-list.md` once established).
4. Fix is released as a patch on all in-support branches simultaneously.
5. CVE is assigned and a GitHub Security Advisory is published.
6. Public disclosure happens after a release-and-update window agreed with the reporter.

## Pre-releases

When ambitious changes need community testing, mythos-agent ships pre-releases:

- **Alpha** (`-alpha.N`) — internal stability, breaking-change exploration
- **Beta** (`-beta.N`) — feature complete, broad testing welcome
- **RC** (`-rc.N`) — release candidate, no further changes barring critical bugs

Pre-releases are published to npm under the `next` dist-tag.

## Reporting a release problem

If a release breaks for you:

- **Regression bug:** open an issue with the `regression` label and the affected version
- **Security issue in a release:** see [SECURITY.md](SECURITY.md)
- **Yanked release request:** comment on the release notes; we will yank from npm if a release is materially broken

## Change log of this policy

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication. |
