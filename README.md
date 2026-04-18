<p align="center">
  <h1 align="center">shedu</h1>
  <p align="center"><strong>The AI security agent that guards your code.</strong></p>
  <p align="center"><em>The Shedu — an open-source autonomous security research agent.</em></p>
</p>

<p align="center">
  <a href="https://github.com/zhijiewong/shedu/actions"><img src="https://github.com/zhijiewong/shedu/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/shedu"><img src="https://img.shields.io/npm/v/shedu" alt="npm"></a>
  <a href="https://github.com/zhijiewong/shedu/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-green" alt="Node">
  <img src="https://img.shields.io/badge/scanners-49-purple" alt="Scanners">
  <img src="https://img.shields.io/badge/rules-329%2B-orange" alt="Rules">
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

shedu **reasons about your code like a security researcher** — generating hypotheses about what could go wrong, finding variants of known CVEs, proving exploitability with PoC exploits, and auto-fixing what it finds. Inspired by the same research direction as Anthropic's proprietary Mythos security agent; not a clone, not affiliated. See [VISION.md](VISION.md) for the full framing.

> **For new contributors:** the active 6-month working plan is in the pinned issue **`[Roadmap] shedu H1 2026 Goals`**. Look for 🙋 markers — those are items where help is wanted. New here? See [CONTRIBUTING.md](CONTRIBUTING.md) for `good-first-issue` guidance.
>
> **For security teams and EU CRA-compliant downstream manufacturers:** see [SECURITY.md](SECURITY.md) for our vulnerability disclosure SLAs, [docs/security/cra-stance.md](docs/security/cra-stance.md) for our EU CRA role declaration, [docs/security/threat-model.md](docs/security/threat-model.md) for our public threat model, and [RELEASES.md](RELEASES.md) for our versioning, LTS, and EOL policy. OpenSSF Best Practices Badge (Passing) submission targeted **June 2026**; releases are signed via [Sigstore](docs/security/sbom.md) and ship with [CycloneDX SBOMs](docs/security/sbom.md) for downstream Manufacturer compliance.

```bash
npx shedu hunt
```

```
🔐 shedu hunt — Autonomous Security Agent

✔ Phase 1: Reconnaissance — 12 entry points, express, typescript, postgresql
✔ Phase 2: Hypothesis — 8 security hypotheses generated
✔ Phase 3: Analysis — 15 findings (semgrep, gitleaks, trivy, built-in), 22 false positives dismissed
✔ Phase 4: Exploitation — 2 attack chains, 3 PoCs

🧪 Security Hypotheses

  [HIGH] HYPO-001 — Race condition: concurrent payment requests could double-charge
    src/payments.ts:45 (race-condition)
  [HIGH] HYPO-002 — Auth bypass: JWT token not validated after password change
    src/auth.ts:78 (auth-bypass)

📊 Confidence Summary

  3 confirmed | 8 likely | 4 possible | 22 dismissed

⛓️ VULNERABILITY CHAINS

 CRITICAL  SQL Injection → Auth Bypass → Data Exfiltration
  ├── src/api/search.ts:45      — unsanitized input in SQL query
  ├── src/middleware/auth.ts:88  — JWT verification skippable
  └── src/api/export.ts:23      — bulk export has no ACL

💣 Proof of Concepts

  SPX-0001 — SQL injection in search endpoint
    curl 'http://target/api/search?q=%27%20OR%201%3D1--'

  Trust Score: 2.3/10 — critical issues found
```

## Quick Start

```bash
# Install
npm install -g shedu

# Quick scan (no API key needed)
shedu scan

# Full autonomous hunt (needs API key)
shedu init
shedu hunt

# Find variants of known CVEs
shedu variants CVE-2021-44228

# Ask security questions
shedu ask "are there any auth bypasses?"

# Check available tools
shedu tools
```

## How It Works

shedu combines **three things no other open-source tool does together**:

### 1. Hypothesis-Driven Scanning
Instead of matching known patterns, the AI **reasons about what COULD go wrong** — generating hypotheses like "this transaction doesn't lock the row, potential race condition" or "this auth check uses string comparison, potential timing attack."

### 2. Variant Analysis (Big Sleep technique)
Given a known CVE, shedu finds **structurally similar but syntactically different** code in your codebase. Same root cause, different location. This is how Google's Big Sleep found 20 real zero-days.

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

`shedu hunt` runs the full multi-agent pipeline:

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
shedu variants CVE-2021-44228

# Auto-detect and scan for variants
shedu variants --auto
```

The variant analyzer extracts the **root cause pattern** from the CVE (not the surface syntax) and searches your codebase for structurally similar code.

## Scanners (49 categories, 329+ rules)

| Category | What it finds | Rules |
|----------|-------------|-------|
| Code patterns | SQLi, XSS, command injection, eval, SSRF, etc. | 25+ |
| Framework rules | React, Next.js, Express, Django, Flask, Spring, Go | 27 |
| Secrets | AWS, GitHub, Stripe, API keys, DB URLs, private keys + entropy | 22 |
| Dependencies (SCA) | Known CVEs via OSV API (10 lockfile formats) | OSV |
| IaC | Docker, Terraform, Kubernetes misconfigurations | 13 |
| AI/LLM Security | Prompt injection, unsafe eval of AI output, cost attacks | 13 |
| API Security | OWASP API Top 10: BOLA, mass assignment, broken auth | 12 |
| Cloud Misconfig | AWS/Azure/GCP: public storage, wildcard IAM, open firewalls | 14 |
| Supply Chain | Typosquatting, dependency confusion, dangerous install scripts | 12 |
| Crypto Audit | Weak hashes, ECB mode, hardcoded keys, deprecated TLS | 11 |
| Zero Trust | Service trust, mTLS, network segmentation, IP-based auth | 8 |
| Privacy/GDPR | PII handling, consent, data retention (GDPR article mapping) | 9 |
| Race Conditions | TOCTOU, non-atomic ops, double-spend, missing transactions | 7 |
| Security Headers | CSP, HSTS, X-Frame-Options, Referrer-Policy | 8 |
| GraphQL | Introspection, depth limit, field auth, batching | 8 |
| WebSocket | Auth, origin check, message validation, broadcast XSS | 7 |
| JWT | Algorithm, expiry, storage, revocation, audience | 9 |
| CORS | Origin reflection, credentials handling, substring bypass | 7 |
| OAuth/OIDC | Missing state, no PKCE, implicit flow, client secret exposure | 7 |
| SSTI | Jinja2, EJS, Handlebars, Pug, Nunjucks, Twig, Go templates | 7 |
| Session | Fixation, expiry, cookie flags, localStorage tokens | 7 |
| + 28 more | SQL injection deep, XSS deep, NoSQL, command injection, deserialization, upload, logging, error handling, ReDoS, memory safety, path traversal, open redirect, XXE, DNS rebinding, clickjacking, subdomain, email, cache, env variables, dep confusion, business logic, permissions, input validation, git history, taint engine, DAST fuzzer, hypothesis agent, variant analysis | 100+ |

**External tool integrations:** Semgrep (30+ languages), Gitleaks (100+ patterns), Trivy (SCA + containers), Checkov (1000+ IaC policies), Nuclei (9000+ DAST templates)

## Integrations

| Platform | What |
|----------|------|
| **VS Code** | Extension with inline diagnostics + one-click AI fix |
| **GitHub Action** | Scan on push/PR + SARIF upload to Code Scanning |
| **PR Review Bot** | Inline comments on vulnerable lines in pull requests |
| **Dashboard** | Local web UI at `shedu dashboard` |
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

| Feature | shedu | Semgrep | Snyk | CodeQL | Nuclei |
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
git clone https://github.com/zhijiewong/shedu.git
cd shedu && npm install && npm run build && npm test
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
