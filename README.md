<p align="center">
  <h1 align="center">sphinx-agent</h1>
  <p align="center"><strong>The AI security agent that guards your code.</strong></p>
  <p align="center">Open-source Mythos for everyone.</p>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#commands">Commands</a> &bull;
  <a href="#hunt-mode">Hunt Mode</a> &bull;
  <a href="#variant-analysis">Variant Analysis</a> &bull;
  <a href="#integrations">Integrations</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

Anthropic's Mythos finds zero-day vulnerabilities for 40 elite organizations. **sphinx-agent** brings that capability to everyone.

Unlike traditional scanners that match known patterns, sphinx-agent **reasons about your code like a security researcher** — generating hypotheses about what could go wrong, finding variants of known CVEs, proving exploitability with PoC exploits, and auto-fixing what it finds.

```bash
npx sphinx-agent hunt
```

```
🔐 sphinx-agent hunt — Autonomous Security Agent

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
npm install -g sphinx-agent

# Quick scan (no API key needed)
sphinx-agent scan

# Full autonomous hunt (needs API key)
sphinx-agent init
sphinx-agent hunt

# Find variants of known CVEs
sphinx-agent variants CVE-2021-44228

# Ask security questions
sphinx-agent ask "are there any auth bypasses?"

# Check available tools
sphinx-agent tools
```

## How It Works

sphinx-agent combines **three things no other open-source tool does together**:

### 1. Hypothesis-Driven Scanning
Instead of matching known patterns, the AI **reasons about what COULD go wrong** — generating hypotheses like "this transaction doesn't lock the row, potential race condition" or "this auth check uses string comparison, potential timing attack."

### 2. Variant Analysis (Big Sleep technique)
Given a known CVE, sphinx-agent finds **structurally similar but syntactically different** code in your codebase. Same root cause, different location. This is how Google's Big Sleep found 20 real zero-days.

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

`sphinx-agent hunt` runs the full multi-agent pipeline:

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
sphinx-agent variants CVE-2021-44228

# Auto-detect and scan for variants
sphinx-agent variants --auto
```

The variant analyzer extracts the **root cause pattern** from the CVE (not the surface syntax) and searches your codebase for structurally similar code.

## Scanners

| Scanner | What it finds | Source |
|---------|-------------|--------|
| Pattern rules | 25+ rules across 6 languages (SQLi, XSS, eval, etc.) | Built-in |
| Secrets | 22 patterns (AWS, GitHub, Stripe, etc.) + Shannon entropy | Built-in |
| Dependencies | Known CVEs in lockfiles (10 formats) | OSV API |
| IaC | Docker, Terraform, Kubernetes misconfigs (13 rules) | Built-in |
| Semgrep | 1000+ community rules, 30+ languages | External |
| Gitleaks | 100+ secret patterns | External |
| Trivy | SCA + containers + IaC + secrets | External |
| Checkov | 1000+ IaC policies | External |
| Nuclei | 9000+ DAST templates | External |
| Taint engine | Source-to-sink data flow tracking | Built-in |
| Hypothesis agent | AI-generated security hypotheses | AI |
| Variant analyzer | CVE variant detection | AI |
| Smart fuzzer | AI-guided payload generation with feedback loop | AI |

## Integrations

| Platform | What |
|----------|------|
| **VS Code** | Extension with inline diagnostics + one-click AI fix |
| **GitHub Action** | Scan on push/PR + SARIF upload to Code Scanning |
| **PR Review Bot** | Inline comments on vulnerable lines in pull requests |
| **Dashboard** | Local web UI at `sphinx-agent dashboard` |
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

| Feature | sphinx-agent | Semgrep | Snyk | CodeQL | Nuclei |
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
git clone https://github.com/sphinx-agent/sphinx-agent.git
cd sphinx-agent && npm install && npm run build && npm test
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
