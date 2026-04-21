<p align="center">
  <img alt="mythos-agent — Cerby the guard puppy" src="assets/cerby-banner.svg" width="640">
</p>

<p align="center">
  <img alt="mythos-agent — 10-second security check demo" src="assets/demo.gif" width="720">
</p>

<p align="center">
  <h1 align="center">mythos-agent</h1>
  <p align="center"><strong>AI code-review assistant for application security.</strong></p>
  <p align="center"><em>Open-source. Reads your code, flags likely security issues, explains its reasoning, suggests fixes.</em></p>
</p>

<p align="center">
  <a href="https://github.com/mythos-agent/mythos-agent/actions"><img src="https://github.com/mythos-agent/mythos-agent/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/mythos-agent"><img src="https://img.shields.io/npm/v/mythos-agent" alt="npm"></a>
  <a href="https://github.com/mythos-agent/mythos-agent/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <a href="https://mythos-agent.com/discord"><img src="https://img.shields.io/badge/discord-join-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D20-green" alt="Node">
  <img src="https://img.shields.io/badge/scanners-15_wired-5B2A86" alt="Wired scanners">
  <img src="https://img.shields.io/badge/experimental-28-6B7280" alt="Experimental scanners">
  <img src="https://img.shields.io/badge/rules-329%2B-FB923C" alt="Rules">
</p>

<p align="center">
  <strong><a href="https://mythos-agent.com">mythos-agent.com</a></strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#commands">Commands</a> &bull;
  <a href="#hunt-mode">Hunt Mode</a> &bull;
  <a href="#variant-analysis">Variant Analysis</a> &bull;
  <a href="#integrations">Integrations</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="VISION.md">Vision</a> &bull;
  <a href="ROADMAP.md">Roadmap</a>
</p>

---

mythos-agent **reviews your code the way a reviewer on a security-focused team would** — walking through likely issue patterns, checking for variants of known CVEs, ranking findings by confidence, and suggesting fixes you can accept or reject. Inspired by the same research direction as Anthropic's proprietary Mythos security agent; not a clone, not affiliated. See [VISION.md](VISION.md) for the full framing.

> **For new contributors:** the active 6-month working plan is in the pinned issue **`[Roadmap] mythos-agent H1 2026 Goals`**. Look for 🙋 markers — those are items where help is wanted. New here? See [CONTRIBUTING.md](CONTRIBUTING.md) for `good-first-issue` guidance.
>
> **For security teams and EU CRA-compliant downstream manufacturers:** see [SECURITY.md](SECURITY.md) for our vulnerability disclosure SLAs, [docs/security/cra-stance.md](docs/security/cra-stance.md) for our EU CRA role declaration, [docs/security/threat-model.md](docs/security/threat-model.md) for our public threat model, and [RELEASES.md](RELEASES.md) for our versioning, LTS, and EOL policy. OpenSSF Best Practices Badge (Passing) submission targeted **June 2026**; releases are signed via [Sigstore](docs/security/sbom.md) and ship with [CycloneDX SBOMs](docs/security/sbom.md) for downstream Manufacturer compliance.

```bash
npx mythos-agent hunt
```

```
🔐 mythos-agent hunt — AI Code-Review Assistant

✔ Phase 1: Reconnaissance — 12 entry points, express, typescript, postgresql
✔ Phase 2: Hypothesis — 8 security hypotheses generated
✔ Phase 3: Analysis — 15 findings (semgrep, gitleaks, trivy, built-in), 22 false positives dismissed
✔ Phase 4: Reproduction — 2 finding chains, 3 reproductions

🧪 Security Hypotheses

  [HIGH] HYPO-001 — Race condition: concurrent payment requests could double-charge
    src/payments.ts:45 (race-condition)
  [HIGH] HYPO-002 — Auth bypass: JWT token not validated after password change
    src/auth.ts:78 (auth-bypass)

📊 Confidence Summary

  3 confirmed | 8 likely | 4 possible | 22 dismissed

⛓️ FINDING CHAINS

 CRITICAL  SQL Injection → Auth Bypass → Data Exfiltration
  ├── src/api/search.ts:45      — unsanitized input in SQL query
  ├── src/middleware/auth.ts:88  — JWT verification skippable
  └── src/api/export.ts:23      — bulk export has no ACL

🧪 Reproductions

  SPX-0001 — SQL injection in search endpoint
    See repro steps in docs/reproductions/SPX-0001.md

  Trust Score: 2.3/10 — critical issues found
```

## Quick Start

```bash
# Install
npm install -g mythos-agent

# Quick scan (no API key needed)
mythos-agent scan

# Full autonomous hunt (needs API key)
mythos-agent init
mythos-agent hunt

# Find variants of known CVEs
mythos-agent variants CVE-2021-44228

# Ask security questions
mythos-agent ask "are there any auth bypasses?"

# Check available tools
mythos-agent tools
```

## How It Works

mythos-agent combines **three things no other open-source tool does together**:

### 1. Hypothesis-Driven Scanning
Instead of matching known patterns, the AI **reasons about what COULD go wrong** — generating hypotheses like "this transaction doesn't lock the row, potential race condition" or "this auth check uses string comparison, potential timing attack."

### 2. Variant Analysis (Big Sleep technique)
Given a known CVE, mythos-agent finds **structurally similar but syntactically different** code in your codebase. Same root cause, different location. This is how Google's Big Sleep found 20 real zero-days.

### 3. Multi-Stage Verification
Every finding goes through a confidence pipeline:
- **Pattern scan** → candidate
- **AI hypothesis** → theoretical risk confirmed
- **Smart fuzzer** → dynamically tested
- **PoC generator** → concrete exploit proves it's real

Only findings that survive multiple stages are reported as "confirmed."

## Commands

| Command | Description |
|---------|-------------|
| `hunt [path]` | Full autonomous multi-agent scan (Recon → Hypothesize → Analyze → Exploit) |
| `scan [path]` | Standard scan (patterns + secrets + deps + IaC + AI) |
| `variants [cve-id]` | Find variants of known CVEs in your codebase |
| `fix [path]` | AI-generated patches with `--apply` |
| `ask [question]` | Natural language security queries |
| `taint [path]` | AI data flow / taint analysis |
| `watch` | Continuous monitoring — scan on file save |
| `dashboard` | Local web UI with charts and findings table |
| `report [path]` | Export as terminal / JSON / HTML / SARIF |
| `policy` | Policy-as-code with SOC2/HIPAA/PCI/OWASP compliance |
| `rules` | Community rule pack registry (search/install/publish) |
| `tools` | Check which external security tools are installed |
| `init` | Setup wizard (Anthropic, OpenAI, Ollama, LM Studio) |

## Hunt Mode

`mythos-agent hunt` runs the full multi-agent pipeline:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    Recon     │ →   │  Hypothesis  │ →   │   Analyze    │ →   │   Exploit    │
│    Agent     │     │    Agent     │     │    Agent     │     │    Agent     │
├──────────────┤     ├──────────────┤     ├──────────────┤     ├──────────────┤
│ Map entry    │     │ Reason about │     │ All scanners │     │ Chain vulns  │
│ points, auth │     │ what could   │     │ + external   │     │ + generate   │
│ boundaries,  │     │ go wrong per │     │ tools + AI   │     │ PoC exploits │
│ data stores  │     │ function     │     │ verification │     │              │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

## Variant Analysis

Find code in your project that has the same root cause as known CVEs:

```bash
# Search for Log4Shell-like patterns
mythos-agent variants CVE-2021-44228

# Auto-detect and scan for variants
mythos-agent variants --auto
```

The variant analyzer extracts the **root cause pattern** from the CVE (not the surface syntax) and searches your codebase for structurally similar code.

## Scanners (15 wired + 28 experimental, 329+ rules)

The **Default** scanners run on every `mythos-agent scan`. **Experimental** scanners are implemented + unit-tested classes that ship in the tarball but are not yet reachable from any CLI, HTTP, MCP, or agent entry point — tracked by [`KNOWN_EXPERIMENTAL`](src/scanner/__tests__/wiring-invariant.test.ts) in the wiring-invariant test.

| Category | What it finds | Rules | Status |
|----------|---------------|-------|--------|
| Code patterns | SQLi, XSS, command injection, eval, SSRF, etc. | 25+ | Default |
| Framework rules | React, Next.js, Express, Django, Flask, Spring, Go | 27 | Default |
| Secrets | AWS, GitHub, Stripe, API keys, DB URLs, private keys + entropy | 22 | Default |
| Dependencies (SCA) | Known CVEs via OSV API (10 lockfile formats) | OSV | Default |
| IaC | Docker, Terraform, Kubernetes misconfigurations | 13 | Default |
| AI/LLM Security | Prompt injection, unsafe eval of AI output, cost attacks | 13 | Default |
| API Security | OWASP API Top 10: BOLA, mass assignment, broken auth | 12 | Default |
| Cloud Misconfig | AWS/Azure/GCP: public storage, wildcard IAM, open firewalls | 14 | Default |
| Security Headers | CSP, HSTS, X-Frame-Options, Referrer-Policy | 8 | Default |
| JWT | Algorithm, expiry, storage, revocation, audience | 9 | Default |
| Session | Fixation, expiry, cookie flags, localStorage tokens | 7 | Default |
| Business Logic | Negative amounts, coupon reuse, inventory races, role escalation | 6 | Default |
| Crypto Audit | Weak hashes, ECB mode, hardcoded keys, deprecated TLS | 11 | Default |
| Privacy/GDPR | PII handling, consent, data retention (GDPR article mapping) | 9 | Default |
| Race Conditions | TOCTOU, non-atomic ops, double-spend, missing transactions | 7 | Default |
| ReDoS | Catastrophic backtracking in regex (nested quantifiers, overlapping alternatives) | — | Default |
| Supply Chain | Typosquatting, dependency confusion, dangerous install scripts | 12 | Experimental |
| Zero Trust | Service trust, mTLS, network segmentation, IP-based auth | 8 | Experimental |
| GraphQL | Introspection, depth limit, field auth, batching | 8 | Experimental |
| WebSocket | Auth, origin check, message validation, broadcast XSS | 7 | Experimental |
| CORS | Origin reflection, credentials handling, substring bypass | 7 | Experimental |
| OAuth/OIDC | Missing state, no PKCE, implicit flow, client secret exposure | 7 | Experimental |
| SSTI | Jinja2, EJS, Handlebars, Pug, Nunjucks, Twig, Go templates | 7 | Experimental |

<details>
<summary>Additional experimental scanners (21 more, not yet wired into default scan)</summary>

SQL injection deep, XSS deep, NoSQL, command injection, deserialization, path traversal, open redirect, XXE, input validation, clickjacking, DNS rebinding, subdomain enumeration, dep confusion, environment variables, logging, error handling, cache, email, upload, memory safety, permissions.

Each exists as a class under `src/scanner/` and has unit tests in `src/scanner/__tests__/coverage-scanners.test.ts` / `new-scanners.test.ts`, but is not invoked by any CLI command, HTTP API route, MCP handler, or agent pipeline. See `KNOWN_EXPERIMENTAL` in the wiring-invariant test for each scanner's deferral reason. Wiring one up follows the pattern of the HeadersScanner / JwtScanner / SessionScanner / BusinessLogicScanner commits on `main`.

</details>

Beyond the scanners above, mythos-agent ships complementary analyses (not counted in the scanner totals): call-graph + taint engine, DAST smart fuzzer, AI hypothesis agent, variant analysis, and git-history mining.

**External tool integrations:** Semgrep (30+ languages), Gitleaks (100+ patterns), Trivy (SCA + containers), Checkov (1000+ IaC policies), Nuclei (9000+ DAST templates)

## Integrations

| Platform | What |
|----------|------|
| **VS Code** | Extension with inline diagnostics + one-click AI fix |
| **GitHub Action** | Scan on push/PR + SARIF upload to Code Scanning |
| **PR Review Bot** | Inline comments on vulnerable lines in pull requests |
| **Dashboard** | Local web UI at `mythos-agent dashboard` |
| **SARIF** | GitHub Code Scanning, VS Code, any SARIF tool |
| **Policy Engine** | SOC2, HIPAA, PCI-DSS, OWASP compliance mapping |

## AI Providers

| Provider | Models | Cost |
|----------|--------|------|
| **Anthropic** | Claude Sonnet 4, Claude Opus 4.6 | API pricing |
| **OpenAI** | GPT-4o, GPT-4o-mini, o1 | API pricing |
| **Ollama** | Llama, CodeLlama, DeepSeek, Qwen | Free (local) |
| **LM Studio** | Any GGUF model | Free (local) |

Pattern scanning, secrets, deps, and IaC work without any API key.

## Comparison

| Feature | mythos-agent | Semgrep | Snyk | CodeQL | Nuclei |
|---------|-------------|---------|------|--------|--------|
| Pattern scanning | Yes | Best | Yes | Yes | Templates |
| **Hypothesis scanning** | **Yes** | No | No | No | No |
| **Variant analysis** | **Yes** | No | No | Partial | No |
| **AI-guided fuzzing** | **Yes** | No | No | No | Templates |
| **PoC generation** | **Yes** | No | No | No | No |
| AI deep analysis | Yes | No | Limited | No | No |
| Vuln chaining | Yes | No | No | No | No |
| AI auto-fix | Yes | No | Fix PRs | No | No |
| NL queries | Yes | No | No | No | No |
| Secrets | Yes | Yes | Yes | No | No |
| SCA | Yes | No | Best | No | No |
| IaC | Yes | No | Yes | No | Templates |
| DAST | Yes | No | No | No | Best |
| Open source | Yes | Partial | No | Yes | Yes |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

```bash
git clone https://github.com/mythos-agent/mythos-agent.git
cd mythos-agent && npm install && npm run build && npm test
```

### Architecture

```
src/
  agents/         Multi-agent orchestrator + Recon/Hypothesis/Analyzer/Exploit agents
  analysis/       Code parser, call graph, taint engine, variant analyzer, service mapper
  agent/          AI integration, prompts, tools, fix validator
  cli/            15 CLI commands
  dast/           Smart fuzzer, PoC generator, payload library
  policy/         Policy engine + compliance mapping
  report/         Terminal, JSON, HTML, SARIF, dashboard
  rules/          Built-in + custom YAML + community registry
  scanner/        Pattern, secrets, deps, IaC, diff scanners
  store/          Results persistence + incremental cache
  tools/          External tool wrappers (Semgrep, Trivy, etc.)
vscode-extension/ VS Code extension
action/           GitHub Actions
bot/              PR Review Bot
```

## License

MIT
