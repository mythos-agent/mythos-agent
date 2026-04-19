# Changelog

All notable changes to sphinx-agent are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Starting with the next release, entries are generated automatically by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/).

## [3.1.0](https://github.com/mythos-agent/mythos-agent/compare/v3.0.1...v3.1.0) (2026-04-19)


### Added

* **scan:** wire BusinessLogicScanner into default scan pipeline ([a70dd51](https://github.com/mythos-agent/mythos-agent/commit/a70dd517ef002f2ce9cacc5a79319a812434b329))
* **scan:** wire HeadersScanner into default scan pipeline ([4240953](https://github.com/mythos-agent/mythos-agent/commit/42409532dfeb1fa40eef30bf0a841a2668fc77c4))
* **scan:** wire JwtScanner into default scan pipeline ([11c9078](https://github.com/mythos-agent/mythos-agent/commit/11c90788c072a673f2f24aa25e509e7c7953ca6a))
* **scan:** wire SessionScanner into default scan pipeline ([4db372a](https://github.com/mythos-agent/mythos-agent/commit/4db372a5ff6beb85a4bc3e4e1f0b50870f5279fe))


### Fixed

* **agent:** pin temperature=0 on every Claude/OpenAI call for deterministic scans ([e6d1231](https://github.com/mythos-agent/mythos-agent/commit/e6d123162060659d65c63c65fbdc90a5e6370d49))
* **ci:** drop --provenance from publish step (npm rejects it for private repos) ([57dfcbe](https://github.com/mythos-agent/mythos-agent/commit/57dfcbe66d81f9b666bb42702c92cf7dbacf26a8))
* **ci:** skip DCO check on release-please and dependabot PR branches ([f2f5cb5](https://github.com/mythos-agent/mythos-agent/commit/f2f5cb57807bd06bd55ef542992df414c24c46d6))

## [3.0.1](https://github.com/mythos-agent/mythos-agent/compare/v3.0.0...v3.0.1) (2026-04-18)


### Fixed

* **cli:** read --version from package.json and sync description ([c697595](https://github.com/mythos-agent/mythos-agent/commit/c69759529cc7df8231144036023c11e27b45c451))
* harden webhooks, fan out version-from-package.json, drop stale main field ([5703298](https://github.com/mythos-agent/mythos-agent/commit/5703298a5bdebc5debc84b981947b07f455f1111))
* **security:** harden patch sandbox, provider error leak, and LLM prompt isolation ([ffeafc6](https://github.com/mythos-agent/mythos-agent/commit/ffeafc6d2a1e5c42c3286399f4e125dcf97e1020))


### Changed

* **cli:** replace any with real types in map.ts HTML renderer ([f9c99df](https://github.com/mythos-agent/mythos-agent/commit/f9c99df50616809ecd4b244d43ca370456b10d24))

## [3.0.0](https://github.com/zhijiewong/shedu/compare/v2.0.2...v3.0.0) (2026-04-18)


### ⚠ BREAKING CHANGES

* rename project to mythos-agent
* rename project to shedu

### Added

* rename project to mythos-agent ([15ba3c5](https://github.com/zhijiewong/shedu/commit/15ba3c5b1343dc14f2b7c4380e810a7f69f16ac7))
* rename project to shedu ([3b4522a](https://github.com/zhijiewong/shedu/commit/3b4522abafc498123c45ddd5f2b61fc4b871bb37))

## [2.0.2](https://github.com/zhijiewong/sphinx-agent/compare/v2.0.1...v2.0.2) (2026-04-18)


### Fixed

* **ci:** unblock sbom and sigstore workflows; add verify-release.sh ([97cdd52](https://github.com/zhijiewong/sphinx-agent/commit/97cdd52228e68fb78c851f6d9fa7a941d3813674))

## [2.0.1](https://github.com/zhijiewong/sphinx-agent/compare/v2.0.0...v2.0.1) (2026-04-18)


### Fixed

* **examples:** rule-pack test.js stands alone; readme surfaces signing + sbom ([4d6d98a](https://github.com/zhijiewong/sphinx-agent/commit/4d6d98a307acc4b34ca3dc0f2f58e898cb09d4d8))


### Documentation

* add chaoss health metrics, research agenda, sphinx benchmark spec, dogfood rfc ([8244b7e](https://github.com/zhijiewong/sphinx-agent/commit/8244b7efd8a95cda722d7f0f895bdf013128b88f))
* **community:** add pioneers leaderboard, scanner SDK spec, bounty draft, seed script ([5896a3c](https://github.com/zhijiewong/sphinx-agent/commit/5896a3c9f4cb9ac18418bd59da44282f7ca313bc))
* **governance:** add tsc evolution, rfc process, maintainer area model, funding stack ([b9bbb3b](https://github.com/zhijiewong/sphinx-agent/commit/b9bbb3b39370e1434d8d727a4fad4e494887b863))
* introduce VISION.md, refresh ROADMAP.md, add H1 2026 goals issue template ([7e2aeec](https://github.com/zhijiewong/sphinx-agent/commit/7e2aeec3d9e886b2c71055d9e038b6b19077bd2a))
* **security:** add CRA stance, SECURITY SLAs, OpenSSF badge prep, RELEASES policy ([e3adeca](https://github.com/zhijiewong/sphinx-agent/commit/e3adeca57429daf416e3ab29023ad643bc526d43))

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
