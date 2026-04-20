# mythos-agent — Threat Model

> Public threat model for mythos-agent itself. Not a threat model for code that mythos-agent scans.
> **Last reviewed:** 2026-04-18.
> **Review cadence:** Annually, or whenever a new attack class is in scope (e.g., new agent provider, new MCP server capability).

## Why this exists

Security tools are high-value targets. The Trivy `aquasecurity/trivy-action` GitHub Action was compromised twice in 2025–2026 (most recently March 2026, v0.69.4 contained a credential stealer for ~12 hours). For a scanner that downstream users *trust to find security issues*, a compromise propagates harm at the speed of CI.

This document explains what we are defending against, what we are explicitly not defending against, and which artifacts in the repository implement which mitigation.

## Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | The `mythos-agent` npm package | Distributed code; the most likely target |
| A2 | The release-signing key material | Compromise enables silent malicious releases |
| A3 | Maintainer GitHub account(s) | Compromise allows arbitrary code merges and releases |
| A4 | The repository itself (source code, workflows, branch protection) | Provides every other asset's integrity |
| A5 | Issue / PR / Discussion content | Phishing surface; data exfiltration target |
| A6 | Findings reported by mythos-agent users | May contain customer code or vulnerability details |
| A7 | API keys held in user `~/.mythos-agent/config.json` | LLM-provider credentials; not held by the project, but the project's input handling matters |

## Adversaries (and what they want)

| ID | Adversary | Motivation |
|---|---|---|
| T1 | Opportunistic supply-chain attacker | Mass compromise via popular package. Credential theft, cryptominer install, downstream supply-chain pivots. |
| T2 | Targeted attacker against a specific downstream user | Use mythos-agent as an entry point into a high-value organization that runs it in CI. |
| T3 | Malicious contributor | Land subtly malicious code via PR; abuse the scanner-rule plugin SDK to ship a backdoored rule. |
| T4 | Compromised maintainer machine | Local malware on the lead maintainer's workstation tampers with releases. |
| T5 | Sponsor / vendor with leverage | Pressure to add a backdoor or to relicense (Gitleaks-style). |
| T6 | Researcher misusing mythos-agent against a system they don't own | Reputational risk for the project. |
| T7 | Adversarial input via scanned codebase | Crafted code that exploits a parser bug or AI prompt-injection in mythos-agent itself. |
| T8 | LLM-provider compromise / outage | Provider returns malicious or misleading output; project unable to scan. |

## Attack surfaces and mitigations

### S1 — The npm package distribution channel

**Attacks:** account takeover, malicious package republish, typosquat, dependency-confusion against private installs.

**Mitigations in place / planned:**

- npm package publish requires `id-token: write` and uses `--provenance` ([release-please.yml](../../.github/workflows/release-please.yml) line 47) — already live
- Sigstore keyless signing of release artifacts via cosign ([sigstore-release.yml](../../.github/workflows/sigstore-release.yml)) — added H1 2026
- SLSA L3 build provenance attestation via `actions/attest-build-provenance` — added H1 2026
- npm 2FA mandatory for the maintainer account (out-of-band; see "Out-of-band controls" below)
- Release verification documented at `scripts/verify-release.sh` (lands with this PR)

### S2 — The release-signing pipeline

**Attacks:** stolen signing key, OIDC misconfiguration allowing untrusted workflow to sign, key-substitution attack.

**Mitigations:**

- Keyless signing — no long-lived signing key exists to steal
- OIDC identity check enforced by verification snippet (must match the workflow path on the canonical repo)
- `id-token: write` permission scoped per-job, never repository-wide

### S3 — Maintainer GitHub accounts

**Attacks:** phishing, session hijack, MFA reset abuse, lost device.

**Mitigations:**

- 2FA mandatory at organization level — declared in [GOVERNANCE.md](../../GOVERNANCE.md) Phase 1 onwards
- Hardware-key (FIDO2) preferred; SMS / TOTP discouraged
- CODEOWNERS-based review enforced for any change to `.github/workflows/`, `package.json`, `release-please-config.json`
- Branch protection on `main`: required PR review, required passing checks, no force-push
- Personal access tokens minimized; prefer fine-grained tokens scoped to the repo

### S4 — The repository itself

**Attacks:** force-push to main, branch-protection bypass, workflow tampering.

**Mitigations:**

- Branch protection on `main` and `release/*` branches
- All GitHub Actions to be pinned to commit SHA — pinning campaign tracked under the H1 2026 supply-chain bucket; tooling: [`frizbee`](https://github.com/stacklok/frizbee) or [`pin-github-action`](https://github.com/mheap/pin-github-action), maintained by the project automatically afterwards via Dependabot
- `step-security/harden-runner` (planned addition) to monitor and constrain CI egress
- CodeQL on every PR ([codeql.yml](../../.github/workflows/codeql.yml))
- `dependency-review-action` on every PR ([dependency-review.yml](../../.github/workflows/dependency-review.yml))

### S5 — Malicious PRs

**Attacks:** subtle backdoor in a PR, scanner rule that exfiltrates data on match, bumping a dependency to a malicious version.

**Mitigations:**

- All PRs require maintainer review (CODEOWNERS-enforced)
- Untrusted contributors' workflow runs require manual approval (GitHub default for first-time contributors)
- Network egress from CI constrained (planned via harden-runner)
- Scanner SDK contract (lands H1 2026) explicitly restricts what plugin scanners may do (no arbitrary network calls without declaration; sandboxed FS access)

### S6 — Compromised maintainer workstation

**Attacks:** malware tampers with local repo before push; signs releases with stolen keys; modifies `.npmrc`.

**Mitigations:**

- Releases happen exclusively from CI, not from a developer machine
- Keyless signing means no signing key on the workstation to steal
- Conventional Commits + release-please review the diff in PR form before any release
- DCO (Developer Certificate of Origin) sign-off planned for all commits

### S7 — Adversarial scanned input

**Attacks:** code crafted to crash the parser; AI prompt injection in code comments that hijacks the agent; resource exhaustion via deeply nested AST.

**Mitigations:**

- Parsing budget per file; depth limits in tree-sitter integration
- Agent prompts treat scanned code as untrusted data (system prompt isolation; output schema enforcement)
- Output sanitization before display in CLI / report
- No execution of scanned code by default; DAST is opt-in and sandboxed
- Findings escape control characters before terminal rendering

### S8 — LLM provider compromise / output manipulation

**Attacks:** provider returns malicious tool calls; prompt injection from upstream cache; provider outage causes silent failure.

**Mitigations:**

- Tool calls are validated against a strict schema before execution
- File-write side effects from tool calls require explicit user confirmation in CLI
- Multiple providers supported (Claude / OpenAI / Ollama / vLLM) — degradation to local-only path possible
- Fail-closed on schema mismatch rather than fail-open

## Explicitly out of scope

These are real risks that mythos-agent does not attempt to address (not in the threat model):

- **Vulnerabilities in code that mythos-agent scans.** Those are the *target* of analysis, not part of mythos-agent's attack surface. They go through user channels (Discussions or directly upstream).
- **Cryptographic attacks against TLS or the GitHub platform.** We rely on the platform's defenses.
- **Nation-state targeting of the lead maintainer.** Mitigation requires resources beyond a volunteer-run project. Bus-factor work (Phase 2/3 governance) reduces the attack surface but does not eliminate it.
- **Confidentiality of telemetry.** Telemetry is opt-in, count-only, no content (per `docs/telemetry.md` once published). Users who want zero telemetry should disable.
- **Side-channel attacks on the AI provider's infrastructure.**
- **Misuse of mythos-agent against systems the user does not own.** Addressed via the responsible-use notice in README, not via technical controls.

## Out-of-band controls (not in this repo)

These cannot be enforced by repo-only artifacts but matter to the threat model:

- npm publish account 2FA (FIDO2 preferred)
- GitHub organization 2FA enforcement
- DNS / domain control of `mythos-agent.com`
- Email security (SPF / DKIM / DMARC) for `security@mythos-agent.com`
- Maintainer workstation: full-disk encryption, OS auto-updates, no shared accounts
- Backup and recovery: signed backups of release-please manifest and `.npmrc` configuration

## Verification of mitigations

Each mitigation above corresponds to a specific repo artifact (workflow, doc, policy). The annual threat-model review:

1. Confirms each artifact still exists and is current.
2. Re-runs `cosign verify-blob` against the latest release using the published verification command.
3. Re-runs `npm audit` and reviews the dependency tree against the SBOM.
4. Confirms branch protection and 2FA settings via the GitHub API.
5. Updates this document with new attack classes observed in the year (e.g., new MCP server attack patterns).

## References

- [SLSA framework](https://slsa.dev/)
- [Sigstore documentation](https://docs.sigstore.dev/)
- [OpenSSF Best Practices Badge — security criteria](https://www.bestpractices.dev/en/criteria#security)
- [Trivy supply-chain incident, March 2026](https://github.com/aquasecurity/trivy/discussions/10402)
- [npm provenance documentation](https://docs.npmjs.com/generating-provenance-statements)

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication. |
