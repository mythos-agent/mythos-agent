# sphinx-agent Launch Kit

Everything you need to publish and promote sphinx-agent on launch day.

---

## Pre-Launch Checklist

- [ ] Create GitHub org `sphinx-agent` and transfer repo from `zhijiewong/sphinx-agent`
- [ ] Update `package.json` repository/homepage URLs to new org
- [ ] Make repo public
- [ ] `npm publish` (first publish claims the package name)
- [ ] Buy domain: sphinx-agent.dev
- [ ] Set GitHub repo description: "The AI security agent that guards your code. 49 scanners, 329+ rules, 58 commands. Open-source Mythos for everyone."
- [ ] Add GitHub topics: `security`, `scanner`, `ai`, `sast`, `dast`, `vulnerability`, `owasp`, `cybersecurity`, `cli`, `typescript`, `devsecops`, `appsec`, `llm-security`
- [ ] Upload social preview image (1280x640)
- [ ] Enable GitHub Discussions
- [ ] Pin repo on your GitHub profile

---

## Hacker News Post

### Title (under 80 chars)
```
Show HN: sphinx-agent – AI security agent with 49 scanners and 329 rules (OSS)
```

### Body
```
Hi HN,

I built sphinx-agent, an open-source AI security agent inspired by Anthropic's Mythos. Unlike traditional scanners that match known patterns, sphinx-agent reasons about your code like a security researcher.

What makes it different:

- Hypothesis-driven scanning: AI generates security hypotheses about what COULD go wrong in each function (not just pattern matching)
- Variant analysis: Given a known CVE, finds structurally similar code in your codebase (Google Big Sleep technique)
- AI-guided fuzzing: Sends payloads, analyzes responses, generates smarter payloads in a feedback loop
- PoC generation: Creates concrete exploit scripts that prove vulnerabilities are real

By the numbers:
- 49 scanner categories (code, secrets, deps, IaC, AI/LLM, API, cloud, supply chain, crypto, zero trust, privacy/GDPR, GraphQL, WebSocket, JWT, CORS, OAuth, SSTI, session, race conditions, and more)
- 329+ built-in rules
- 58 CLI commands
- 8 languages (TypeScript, JavaScript, Python, Go, Java, PHP, C/C++, Rust)
- Works with Claude, GPT-4o, Ollama, or any OpenAI-compatible model
- VS Code extension, GitHub Action, MCP server, REST API
- Full OWASP Top 10 coverage

Quick start:
  npx sphinx-agent scan        # pattern scan (no API key needed)
  npx sphinx-agent hunt        # full AI-powered security hunt
  npx sphinx-agent quick       # 10-second security check

GitHub: https://github.com/sphinx-agent/sphinx-agent

Built with TypeScript. MIT licensed. 25K lines, 96 tests, 4 code reviews.

I'd love feedback on the scanning approach and what vulnerability categories I should add next.
```

---

## Twitter / X Posts

### Main Launch Tweet
```
🔐 Introducing sphinx-agent — the AI security agent that guards your code.

Open-source Mythos for everyone.

→ 49 scanner categories
→ 329+ built-in rules
→ AI hypothesis scanning (not just pattern matching)
→ CVE variant analysis (Big Sleep technique)
→ AI-guided fuzzing with PoC generation

npx sphinx-agent scan

github.com/sphinx-agent/sphinx-agent
```

### Thread Post 2 — What Makes It Different
```
What makes sphinx-agent different from Semgrep/Snyk/CodeQL?

1️⃣ It REASONS about code, not just matches patterns
2️⃣ It generates hypotheses: "this function could be vulnerable because..."
3️⃣ It finds variants of known CVEs
4️⃣ It proves vulnerabilities with concrete PoC exploits
5️⃣ It chains findings into multi-step attack paths
```

### Thread Post 3 — Scanner Categories
```
49 scanner categories including:

🤖 AI/LLM Security (prompt injection, cost attacks)
🔑 API Security (OWASP API Top 10)
☁️ Cloud Misconfig (AWS/Azure/GCP)
🔗 Supply Chain (typosquatting, dep confusion)
🔒 Crypto Audit (weak hashes, hardcoded keys)
🛡️ Zero Trust (service auth, mTLS)
🔐 Privacy/GDPR (PII handling, consent)
⚡ Race Conditions (TOCTOU, double-spend)
```

### Thread Post 4 — Quick Demo
```
Try it in 10 seconds:

npx sphinx-agent quick

Output:
🔐 2.3/10 | 3C 8H 2M (13ms)

  🔴 SQL Injection — src/api.ts:45
  🔴 JWT None Algorithm — src/auth.ts:78
  🔴 Hardcoded Secret — src/config.ts:12

  → sphinx-agent fix --severity critical --apply

One command. Instant results.
```

### Thread Post 5 — Call to Action
```
sphinx-agent is MIT licensed and free forever.

⭐ Star if you want to see more AI-powered security tools
🔧 Contribute: we have "good first issue" labels
📦 npm install -g sphinx-agent

github.com/sphinx-agent/sphinx-agent

Built with Claude Opus 4.6 — 25K lines in a single coding session.
```

---

## Reddit Posts

### r/netsec Post
```
Title: sphinx-agent: Open-source AI security scanner with 49 categories, 329+ rules, hypothesis-driven scanning

I built an open-source security scanner that uses AI to reason about code rather than just matching patterns. It combines traditional SAST with AI-powered techniques inspired by Google's Big Sleep and Anthropic's Mythos.

Key capabilities:
- Hypothesis-driven scanning: AI generates security hypotheses per function
- CVE variant analysis: finds code similar to known vulnerabilities
- AI-guided fuzzing with feedback loop
- PoC exploit generation for confirmed vulnerabilities
- Multi-agent pipeline: Recon → Hypothesize → Analyze → Exploit

Covers: injection (SQL, NoSQL, command, SSTI), XSS (8 DOM patterns), auth (JWT, OAuth, session), crypto (11 rules), cloud (AWS/Azure/GCP), supply chain, zero trust, privacy/GDPR, GraphQL, WebSocket, and 30+ more categories.

Works with Claude, GPT-4o, or local models (Ollama). Pattern scanning works without any API key.

GitHub: https://github.com/sphinx-agent/sphinx-agent

Feedback welcome — especially from pentesters on what rules/checks are missing.
```

### r/programming Post
```
Title: I built a 25K-line AI security scanner with 49 vulnerability categories in TypeScript

sphinx-agent is an open-source AI security agent. Instead of just matching regex patterns like most SAST tools, it uses AI to reason about what could go wrong in your code.

Some numbers:
- 25K lines of TypeScript
- 329+ built-in security rules
- 49 scanner categories
- 58 CLI commands
- 96 tests, 4 code reviews
- Scans: TS, JS, Python, Go, Java, PHP, C/C++, Rust

The most interesting part: the hypothesis agent reads your functions and generates security hypotheses like "this transaction doesn't lock the row — potential race condition" rather than just matching known patterns.

Try it: npx sphinx-agent scan

GitHub: https://github.com/sphinx-agent/sphinx-agent
```

### r/cybersecurity Post
```
Title: Open-source AI security agent with AI/LLM security scanning, supply chain detection, and zero-trust validation

Releasing sphinx-agent — a CLI security tool that combines 49 scanner categories with AI-powered analysis. A few highlights for this community:

- AI/LLM Security: detects prompt injection, unsafe eval of AI output, API key exposure in client code, cost attacks (13 rules)
- Supply Chain: typosquatting detection, dependency confusion, dangerous install scripts
- Zero Trust: implicit service trust, missing mTLS, overprivileged accounts
- Privacy/GDPR: PII logging, missing consent, data retention (mapped to GDPR articles)
- Compliance reports: SOC2, HIPAA, PCI-DSS, OWASP Top 10 mapping

Also includes a STRIDE threat model generator, security scorecard with letter grades, and secrets rotation guides.

Free, open-source, MIT licensed: https://github.com/sphinx-agent/sphinx-agent
```

---

## LinkedIn Post

```
🔐 Excited to announce sphinx-agent — an open-source AI security agent.

While Anthropic's Mythos finds zero-days for 40 elite organizations, sphinx-agent brings that capability to everyone.

What makes it unique:
→ Hypothesis-driven scanning (AI reasons about what COULD go wrong)
→ CVE variant analysis (finds code similar to known vulnerabilities)
→ 49 scanner categories covering OWASP Top 10, supply chain, AI/LLM security, cloud misconfig, zero trust, and more
→ 329+ built-in rules across 8 programming languages
→ Compliance reporting for SOC2, HIPAA, PCI-DSS, OWASP, and GDPR

For security teams:
• Drop-in CI/CD integration (GitHub Action + SARIF)
• Policy-as-code with compliance mapping
• VS Code extension with inline diagnostics
• REST API and MCP server for tool integration

For developers:
• npx sphinx-agent quick — 10-second security check
• npx sphinx-agent fix --apply — AI-generated patches
• npx sphinx-agent ask "find auth bypasses" — natural language queries

MIT licensed. Free forever.

🔗 GitHub: https://github.com/sphinx-agent/sphinx-agent

#cybersecurity #opensource #devsecops #appsec #ai
```

---

## Product Hunt Tagline Options

1. "The AI security agent that guards your code — open-source Mythos for everyone"
2. "49 security scanners, 329 rules, AI-powered — one npm install"
3. "AI security scanner that reasons about code like a security researcher"

### Product Hunt Description (260 chars)
```
sphinx-agent is an AI security agent with 49 scanner categories and 329+ rules. Unlike pattern matchers, it hypothesizes vulnerabilities, finds CVE variants, generates PoC exploits, and auto-fixes issues. Covers AI/LLM, API, cloud, supply chain, and more.
```

---

## Dev.to / Blog Post Outline

### Title: "I Built an Open-Source Mythos: 25K Lines, 49 Scanners, 329 Rules"

1. **The Problem** — Mythos finds zero-days for 40 companies. Everyone else uses Semgrep.
2. **The Gap** — Pattern matching vs. semantic reasoning. What Big Sleep proved.
3. **The Solution** — sphinx-agent: hypothesis-driven scanning + variant analysis
4. **Architecture** — Multi-agent swarm: Recon → Hypothesize → Analyze → Exploit
5. **Demo** — Walk through scanning a real project, showing hypothesis output
6. **The Numbers** — 49 categories, 329 rules, 58 commands, 4 code reviews
7. **What's Next** — Documentation site, more language support, community rules
8. **Try It** — `npx sphinx-agent scan`

---

## Email to Security Newsletters

### Subject: "Open-source AI security agent with 49 scanner categories"

```
Hi [Name],

I'm launching sphinx-agent, an open-source AI security agent that combines 49 vulnerability scanner categories with AI-powered analysis.

Key differentiators from Semgrep/Snyk:
- Hypothesis-driven scanning (AI reasons about each function)
- CVE variant analysis (Google Big Sleep technique)
- AI-guided fuzzing with PoC generation
- AI/LLM security scanner (prompt injection, cost attacks)
- Compliance mapping (SOC2, HIPAA, PCI-DSS, OWASP, GDPR)

Would this be a good fit for [newsletter name]? Happy to provide more details or a demo.

GitHub: https://github.com/sphinx-agent/sphinx-agent

Best,
[Your name]
```

### Target Newsletters
- tl;dr sec (Clint Gibler)
- This Week in Security
- SANS NewsBites
- Daniel Miessler's Unsupervised Learning
- Console.dev (open-source picks)
- Changelog News
- DevSecOps Weekly

---

## GitHub Release Notes (v2.0.0)

```markdown
## sphinx-agent v2.0.0 — The AI Security Agent

The most comprehensive open-source security scanner available.

### Highlights
- 🧪 **Hypothesis-driven scanning** — AI reasons about what could go wrong
- 🔬 **CVE variant analysis** — find code similar to known vulnerabilities
- 🤖 **49 scanner categories** — from code patterns to AI/LLM security to zero trust
- 🎯 **329+ built-in rules** across 8 programming languages
- 🛡️ **58 CLI commands** covering scanning, fixing, reporting, compliance, and more

### Quick Start
```bash
npm install -g sphinx-agent
sphinx-agent scan
```

### Full Changelog
See [CHANGELOG.md](./CHANGELOG.md)
```

---

## Launch Day Schedule

| Time | Action |
|------|--------|
| 8:00 AM | Make repo public + npm publish |
| 8:05 AM | Post on Hacker News (Show HN) |
| 8:10 AM | Post Twitter thread |
| 8:15 AM | Post on Reddit (r/netsec, r/programming, r/cybersecurity) |
| 8:30 AM | Post on LinkedIn |
| 9:00 AM | Submit to Product Hunt |
| 9:30 AM | Send emails to security newsletters |
| 10:00 AM | Post on Dev.to |
| 12:00 PM | Monitor HN comments, respond to questions |
| 2:00 PM | Cross-post to Chinese dev communities (V2EX, Juejin) |
| 5:00 PM | Post daily metrics update on Twitter |

**Best day to launch: Tuesday or Wednesday**
**Best time for HN: 6-9 AM ET**
