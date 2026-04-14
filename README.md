<p align="center">
  <h1 align="center">sphinx-agent</h1>
  <p align="center"><strong>Agentic AI security scanner — Mythos for everyone.</strong></p>
  <p align="center">Finds vulnerabilities, chains them into attack paths, and generates patches.</p>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#fix-command">Auto-Fix</a> &bull;
  <a href="#github-action">CI/CD</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

Anthropic's [Mythos](https://www.anthropic.com/glasswing) model finds zero-day vulnerabilities for 40 elite organizations. **sphinx-agent** brings that capability to everyone — an open-source, AI-powered security scanner that autonomously analyzes your code, finds vulnerabilities, chains them into exploitable attack paths, and generates patches to fix them.

```bash
npx sphinx-agent scan
```

```
🔐 sphinx-agent v0.2.0 — Agentic AI Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📁 Scanning: ./my-project

✔ Phase 1: Pattern Scan (1.2s) — 31 potential issues in 47 files
✔ Phase 2: AI Deep Analysis (14.3s) — confirmed 9, discovered 3 new, dismissed 22
✔ Phase 3: Vulnerability Chaining (6.1s) — found 2 exploitable chains

⛓️ VULNERABILITY CHAINS

 CRITICAL  SQL Injection → Auth Bypass → Data Exfiltration
  ├── src/api/search.ts:45      — unsanitized input in SQL query
  ├── src/middleware/auth.ts:88  — JWT verification skippable
  └── src/api/export.ts:23      — bulk export has no ACL
  →  An attacker could extract all user data via a crafted search query
  💥 Impact: Full database exfiltration

 HIGH  XSS → Session Hijack
  ├── src/views/profile.tsx:67  — unescaped user bio field
  └── src/config/cookies.ts:12  — session cookie missing HttpOnly
  →  An attacker could steal sessions via profile page injection
  💥 Impact: Account takeover

📊 Summary
  Trust Score: 2.3/10 — critical issues found
```

## Quick Start

```bash
# Install globally
npm install -g sphinx-agent

# Or run directly with npx
npx sphinx-agent scan

# Set up your AI provider (for deep analysis + auto-fix)
sphinx-agent init

# Scan your project
sphinx-agent scan ./my-project

# Pattern-only scan (no AI, no API key needed)
sphinx-agent scan --no-ai

# Scan only git-changed files (great for CI)
sphinx-agent scan --diff

# Auto-fix vulnerabilities
sphinx-agent fix --apply

# Generate reports
sphinx-agent report --html    # beautiful HTML report
sphinx-agent report --sarif   # GitHub Code Scanning format
sphinx-agent report --json    # machine-readable JSON
```

## How It Works

sphinx-agent runs a **3-phase security analysis** inspired by how Anthropic's Mythos model approaches vulnerability discovery:

### Phase 1: Pattern Scan (instant, free)
Fast regex + rule-based scanning for OWASP Top 10 vulnerabilities. 25+ built-in rules covering SQL injection, XSS, command injection, hardcoded secrets, and more. Supports TypeScript, JavaScript, Python, Go, Java, and PHP. No AI needed — runs in milliseconds.

### Phase 2: AI Deep Analysis (agentic)
An AI agent autonomously navigates your codebase — reading files, tracing data flows, following imports — to verify Phase 1 findings and discover new vulnerabilities that patterns miss. Dramatically reduces false positives (typically 70-90% reduction) while finding business logic flaws, auth bypasses, and complex injection paths.

### Phase 3: Vulnerability Chaining (the killer feature)
Analyzes confirmed vulnerabilities to identify **exploitable attack chains** — sequences where one vulnerability enables the next, creating critical attack paths from individually minor issues. This is what sets sphinx-agent apart from traditional scanners.

## Features

- **Agentic AI analysis** — AI autonomously explores your codebase like a security researcher
- **Vulnerability chaining** — discovers how individual vulns combine into critical attack paths
- **Auto-fix** — AI generates patches and applies them with `sphinx-agent fix --apply`
- **25+ built-in rules** — OWASP Top 10 coverage across 6 languages
- **Custom rules** — add your own rules in YAML
- **Massive false positive reduction** — AI dismisses 70-90% of pattern-match false positives
- **Trust Score** — at-a-glance security assessment (0-10)
- **Multiple output formats** — terminal, JSON, HTML, SARIF
- **GitHub Action** — drop-in CI/CD security scanning with Code Scanning integration
- **Diff scanning** — scan only changed files with `--diff` for fast CI feedback
- **Zero config** — works out of the box with `--no-ai` for pattern scanning
- **Multi-language** — TypeScript, JavaScript, Python, Go, Java, PHP

## Fix Command

sphinx-agent can generate and apply AI-powered patches for discovered vulnerabilities:

```bash
# Preview patches (dry run)
sphinx-agent fix

# Apply all patches
sphinx-agent fix --apply

# Fix only critical vulnerabilities
sphinx-agent fix --severity critical --apply

# Fix specific vulnerabilities by ID
sphinx-agent fix --id MYTH-0001 MYTH-0003 --apply
```

```
🔧 sphinx-agent fix — AI-Powered Patch Generation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✔ Generated 3 patches

  MYTH-0001 — src/api/search.ts
  Use parameterized query instead of string concatenation

  - const result = db.query(`SELECT * FROM users WHERE name = '${name}'`);
  + const result = db.query('SELECT * FROM users WHERE name = $1', [name]);

  MYTH-0007 — src/auth/hash.ts
  Replace MD5 with SHA-256

  - return crypto.createHash("md5").update(password).digest("hex");
  + return crypto.createHash("sha256").update(password).digest("hex");
```

## GitHub Action

Add sphinx-agent to your CI/CD pipeline:

```yaml
# .github/workflows/sphinx-agent.yml
name: Security Scan

on: [push, pull_request]

permissions:
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Pattern-only scan (free, no API key)
      - uses: sphinx-agent/sphinx-agent@main
        with:
          severity: medium
          no-ai: "true"
          fail-on: critical

      # Full AI scan (with API key)
      # - uses: sphinx-agent/sphinx-agent@main
      #   with:
      #     api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      #     fail-on: high
```

SARIF results are automatically uploaded to GitHub Code Scanning.

## Vulnerability Coverage

| Category | Languages | CWE |
|----------|-----------|-----|
| SQL Injection | All | CWE-89 |
| Cross-Site Scripting (XSS) | JS/TS, PHP | CWE-79 |
| Command Injection | All | CWE-78 |
| Path Traversal | JS/TS | CWE-22 |
| Hardcoded Secrets | All | CWE-798 |
| Weak Cryptography | All | CWE-327 |
| Insecure Cookies | JS/TS | CWE-614 |
| Dangerous `eval()` | JS/TS, Python, PHP | CWE-95 |
| NoSQL Injection | JS/TS | CWE-943 |
| SSRF | All | CWE-918 |
| Open Redirect | All | CWE-601 |
| JWT Vulnerabilities | All | CWE-345 |
| XML External Entity (XXE) | Java | CWE-611 |
| Insecure Deserialization | Java | CWE-502 |
| File Inclusion | PHP | CWE-98 |

## Custom Rules

Create YAML rules in `.sphinx/rules/`:

```yaml
# .sphinx/rules/my-rules.yml
rules:
  - id: no-cors-wildcard
    title: Wildcard CORS Origin
    description: "Using '*' as CORS origin allows any website to make requests."
    severity: medium
    category: config
    cwe: CWE-942
    languages: [typescript, javascript]
    patterns:
      - pattern: "cors\\s*\\(\\s*\\{[^}]*origin\\s*:\\s*['\"]\\*['\"]"
```

Or pass a rules directory: `sphinx-agent scan --rules ./my-rules/`

## Configuration

Create a `.sphinx.yml` in your project root, or run `sphinx-agent init`:

```yaml
provider: anthropic
model: claude-sonnet-4-20250514
scan:
  include:
    - "**/*.ts"
    - "**/*.js"
    - "**/*.py"
    - "**/*.go"
    - "**/*.java"
    - "**/*.php"
  exclude:
    - "node_modules/**"
    - "dist/**"
    - "**/*.test.*"
  maxFileSize: 100000
  severityThreshold: low
```

Environment variables:
- `MYTHOH_API_KEY` or `ANTHROPIC_API_KEY` — your API key
- `MYTHOH_MODEL` — model override

## Comparison

| Feature | sphinx-agent | Semgrep | CodeQL | Snyk Code |
|---------|--------|---------|--------|-----------|
| Pattern scanning | Yes | Yes | Yes | Yes |
| AI deep analysis | **Yes** | No | No | Limited |
| Vulnerability chaining | **Yes** | No | No | No |
| AI auto-fix | **Yes** | No | No | Limited |
| False positive reduction | **AI-powered** | Manual | Manual | Limited |
| Attack narratives | **Yes** | No | No | No |
| SARIF output | Yes | Yes | Yes | Yes |
| GitHub Action | Yes | Yes | Yes | Yes |
| Custom YAML rules | Yes | Yes | Yes | No |
| Zero config | Yes | No | No | No |
| Open source | Yes | Partial | Yes | No |
| Offline mode | Yes (`--no-ai`) | Yes | Yes | No |

## Contributing

Contributions are welcome! Here's how to get started:

```bash
git clone https://github.com/sphinx-agent/sphinx-agent.git
cd sphinx-agent
npm install
npm run build
node dist/cli/index.js scan ./demo-vulnerable-app --no-ai
```

### Adding new rules

Built-in rules: `src/rules/builtin-rules.ts`
Custom YAML rules: `.sphinx/rules/*.yml`
Example rules: `examples/custom-rules.yml`

Each rule needs: id, title, description, severity, category, languages, and regex patterns.

### Roadmap

- [x] Pattern scanning (25+ rules, 6 languages)
- [x] AI deep analysis with Claude
- [x] Vulnerability chaining
- [x] `sphinx-agent fix` — AI-generated patches
- [x] HTML report generation
- [x] SARIF output (GitHub Code Scanning)
- [x] GitHub Action
- [x] Custom YAML rules
- [x] `--diff` mode (scan changed files only)
- [ ] Semgrep integration for deeper pattern matching
- [ ] Claude Agent SDK migration
- [ ] Local model support (Ollama, vLLM)
- [ ] Watch mode (scan on file save)
- [ ] Config presets (`--preset express|nextjs|django`)
- [ ] Monorepo support
- [ ] More languages (Ruby, C#, Rust)

## License

MIT
