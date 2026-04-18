# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues, Discussions, or social media.**

### How to report

1. **Email:** [security@sphinx-agent.dev](mailto:security@sphinx-agent.dev)
2. **GitHub private vulnerability reporting:** [Report here](https://github.com/zhijiewong/sphinx-agent/security/advisories/new)
3. **PGP key:** A PGP public key for sensitive reports is published at `https://sphinx-agent.dev/.well-known/pgp-key.asc` (publication pending — until then, use GitHub's encrypted private reporting).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact and severity assessment
- Suggested fix (if any)
- Whether you intend to publish details, and on what timeline

## Service-level expectations

These targets are aligned with the OpenSSF Best Practices Badge (Passing tier) and modeled on Checkov's response policy.

| Stage | Target |
|---|---|
| **Acknowledgment** | Within 48 hours |
| **Triage** (severity assessment, scope) | Within 5 business days |
| **Fix or interim mitigation** | Within 14 days of triage for critical/high; within 30 days for medium/low |
| **CVE assignment** | We coordinate with MITRE / GitHub Security Advisories |
| **Public disclosure** | After a fix is released, on a timeline agreed with the reporter |
| **Credit** | Reporter is credited in the release notes and CVE record unless they request anonymity |

If we cannot meet a target, we will tell the reporter why and propose an updated timeline. Interim mitigations (config flags, documentation warnings) may be published before a full fix when the trade-off favors users.

## Scope

This policy covers vulnerabilities **in sphinx-agent itself**:

- The sphinx-agent CLI (`src/`)
- The VS Code extension (`vscode-extension/`)
- The MCP server (`src/mcp/`)
- The REST API server (`src/server/`)
- GitHub Actions (`action/`)
- Docker images published to ghcr.io / Docker Hub
- Build / release workflows in `.github/workflows/`

**Out of scope** (please use the indicated channel):

- **Vulnerabilities discovered *by* sphinx-agent in code being scanned.** These are not vulnerabilities in sphinx-agent. Use community [Discussions](https://github.com/zhijiewong/sphinx-agent/discussions) or report directly to the affected upstream project.
- **Demo / intentionally-vulnerable code** (`demo-vulnerable-app/`) — by design.
- **Third-party tools integrated via subprocess** (Semgrep, Trivy, Gitleaks, Checkov, Nuclei) — report to the respective maintainers.
- **Vulnerabilities in dependencies** — report to the dependency maintainer; we will update once a fix is available upstream.

## Threat model

A public threat model for sphinx-agent itself lives at [`docs/security/threat-model.md`](docs/security/threat-model.md) (publication scheduled in the H1 2026 supply-chain hardening session). Risk classes covered: supply-chain compromise, agent prompt injection, scanner output exfiltration, MCP-server misconfiguration, REST-server exposure.

## Security measures in place

- All subprocess calls use `spawnSync` with argument arrays (no shell injection)
- File operations include path-traversal prevention
- API server binds to 127.0.0.1 by default
- No secrets in source code (API keys via environment variables only)
- CodeQL scanning on every PR
- Dependency review on every PR via `dependency-review.yml`
- Conventional Commits + release-please for auditable release history

The H1 2026 roadmap adds: GitHub Actions pinned to commit SHA, Sigstore-signed releases (cosign), CycloneDX SBOM per release, npm provenance attestations, organization-mandatory 2FA, signed commits.

## Supported versions

| Version | Status | Receives security fixes until |
|---|---|---|
| 2.x | Active | TBD (see [RELEASES.md](RELEASES.md) once published) |
| 1.x | Maintenance | EOL announced 6 months in advance |
| < 1.0 | End of life | Not supported |

## EU Cyber Resilience Act stance

sphinx-agent is currently maintained by an unpaid individual contributor and is **not an Open-Source Steward** under the EU Cyber Resilience Act (Regulation (EU) 2024/2847). Manufacturers integrating sphinx-agent into commercial products retain full CRA responsibility for those products.

The full role declaration, manufacturer guidance, and reporting cooperation policy live at [`docs/security/cra-stance.md`](docs/security/cra-stance.md).

## Recognition

Security researchers who help keep sphinx-agent safe are credited in:

- The CVE record and GitHub Security Advisory
- The release notes for the fix release
- An optional public hall of fame at `docs/security/researchers.md` (opt-in)

If you would like to remain anonymous, say so in your report and we will respect that.

## Bug bounty

sphinx-agent does not currently run a paid bug bounty program for vulnerabilities in the project itself. This may change once sustainable funding is in place; if it does, the program will be announced here and at `docs/bounty.md`. (A separate, unrelated program — paid contributions of *new scanner rules* — is drafted but inactive; see the [community on-ramp section of the roadmap](ROADMAP.md#5-contributor-on-ramp).)
