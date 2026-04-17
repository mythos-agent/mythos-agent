# Changelog

All notable changes to sphinx-agent are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Starting with the next release, entries are generated automatically by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added
- Open-source polish: `GOVERNANCE.md`, `SUPPORT.md`, `MAINTAINERS.md`, `ROADMAP.md` at repo root
- Security workflows: CodeQL analysis and dependency review on PRs
- Automated releases via release-please
- Test coverage reporting (v8) with Codecov upload
- Pre-commit hooks: `lint-staged` for format/lint, `commitlint` for Conventional Commits
- `typecheck` npm script (`tsc --noEmit`)

### Changed
- `CODEOWNERS` expanded with per-directory ownership
- `CHANGELOG.md` now managed by release-please from Conventional Commits

## [2.0.0] - 2026-04-16

### Added
- **49 scanner categories** with ~329 built-in rules
- **AI/LLM Security Scanner** — prompt injection, unsafe eval, cost attacks (13 rules)
- **API Security Scanner** — OWASP API Top 10 coverage (12 rules)
- **Cloud Misconfiguration Scanner** — AWS/Azure/GCP (14 rules)
- **Supply Chain Scanner** — typosquatting, dependency confusion (12 rules)
- **Crypto Audit Scanner** — weak hashes, ECB mode, hardcoded keys (11 rules)
- **Zero Trust Validator** — service trust, mTLS, network segmentation (8 rules)
- **Privacy/GDPR Scanner** — PII handling, consent, data retention (9 rules)
- **Race Condition Detector** — TOCTOU, double-spend, non-atomic ops (7 rules)
- **GraphQL Scanner** — introspection, depth limit, field auth (8 rules)
- **WebSocket Scanner** — auth, origin check, message validation (7 rules)
- **JWT Deep Scanner** — algorithm, expiry, storage, revocation (9 rules)
- **CORS Deep Scanner** — origin reflection, credential handling (7 rules)
- **SSTI Scanner** — Jinja2, EJS, Handlebars, Pug, Nunjucks (7 rules)
- **OAuth Scanner** — state param, PKCE, implicit flow (7 rules)
- **Session Scanner** — fixation, expiry, cookie flags (7 rules)
- **Memory Safety Scanner** — C/C++ buffer overflow, Rust unsafe (9 rules)
- **Business Logic Scanner** — negative amounts, role escalation (6 rules)
- **XSS Deep Scanner** — DOM XSS, template injection, postMessage (8 rules)
- **Hypothesis Agent** — AI-generated security hypotheses per function
- **Variant Analysis** — find CVE variants via Big Sleep technique
- **Smart Fuzzer** — AI-guided payload generation with feedback loop
- **PoC Generator** — concrete exploit scripts for confirmed vulnerabilities
- **MCP Server** — 6 tools for Claude Code, Cursor, Copilot integration
- **REST API Server** — 8 endpoints for programmatic access
- **Pentest Command** — full DAST against live targets
- **Threat Model Generator** — AI-generated STRIDE analysis
- **Compliance Reports** — SOC2, HIPAA, PCI-DSS, OWASP, GDPR
- **Security Scorecard** — letter grade with badge generation
- **Baseline Tracking** — compare findings over time
- **Git History Scanner** — find secrets in commit history
- **Runtime Monitor** — watch logs for security events
- **Secrets Rotation Guide** — step-by-step rotation per provider
- **Notification Webhooks** — Slack, Discord, Teams, custom
- **SBOM Generator** — CycloneDX 1.5 and SPDX 2.3
- **License Compliance** — copyleft detection, deny list
- **Shell Completions** — bash, zsh, fish
- **Docker Deployment** — Dockerfile + docker-compose
- **JetBrains Integration** — external tools config
- 28 framework-specific rules (React, Next.js, Express, Django, Flask, Spring, Go)
- 8 config presets (express, nextjs, django, flask, spring, go, react, fullstack)
- Parallel scanning for 2-4x speedup
- Finding export (CSV, Jira, Linear, GitHub Issues)

### Fixed
- 35 issues across 3 code reviews (security, bugs, architecture)

## [1.0.0] - 2026-04-13

### Added
- Initial release: pattern scanning + AI deep analysis + vulnerability chaining
- 25+ code rules, 22 secret patterns, 13 IaC rules across 6 languages
- CLI commands: scan, fix, ask, taint, watch, dashboard, report, policy, rules, init
- VS Code extension with inline diagnostics and AI quick-fix
- GitHub Action + PR Review Bot
- HTML, JSON, SARIF report formats
- Policy-as-code with compliance mapping
- Custom YAML rules + community rule registry
- Multi-model support (Anthropic, OpenAI, Ollama, LM Studio)
- Incremental scanning with file hash cache
- Git diff scanning mode
