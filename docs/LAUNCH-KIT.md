# mythos-agent Launch Kit

Everything you need to publish and promote mythos-agent on launch day.

Positioning rule: **lead with your own value prop. Don't lean on other companies' products for framing.** Factual backend disclosure (*"works with Claude, GPT-4o, Ollama"*) is fine and necessary; marketing hooks that position this tool as an "open-source version" of a specific commercial product are not.

---

## Pre-Launch Checklist

**Prereqs (done):**
- [x] GitHub org `mythos-agent` created, repo at `github.com/mythos-agent/mythos-agent`
- [x] `package.json` repository/homepage URLs point to the org
- [x] Repo made public
- [x] Brand assets shipped (`cerby-hero.svg`, `cerby-banner.svg`, `cerby-banner-social.png`, favicons, `BRAND.md`)
- [x] README banner + shields on-brand
- [x] HTML reports brand-unified (violet + cyan + Cerby, Geist Mono code font)

**Before posting anywhere:**
- [ ] `npm publish` v3.1.0 (or tag `v1.0.0` as the launch version — cleaner first-impression number)
- [ ] Upload `cerby-banner-social.png` at repo Settings → Social preview (needs repo public, which is done)
- [ ] Upload `web-app-manifest-512x512.png` as GitHub org avatar + npm org avatar
- [ ] Buy and point domain `mythos-agent.com` (optional for launch; nice-to-have)
- [ ] Set GitHub repo description: *"AI code reviewer that reasons about security bugs instead of just matching patterns. 43 scanner categories, 329+ rules, 8 languages. MIT licensed."*
- [ ] Add GitHub topics: `security`, `scanner`, `ai`, `sast`, `dast`, `vulnerability`, `owasp`, `cybersecurity`, `cli`, `typescript`, `devsecops`, `appsec`, `llm-security`
- [ ] Enable GitHub Discussions
- [ ] Pin repo on your GitHub profile
- [ ] Record 15–30 second demo GIF, embed at top of README (see `docs/DEMO-SCRIPT.md` when written)
- [ ] Create 3–5 `good first issue` labels on real issues
- [ ] Pre-warm 5–10 dev friends via DM 48h before launch

---

## Hacker News Post

### Title (under 80 chars)
```
Show HN: mythos-agent – open-source AI code reviewer for security bugs
```

### Body
```
Hi HN,

I built mythos-agent, an open-source AI code-review assistant for application security. It reasons about code the way a security reviewer on a focused team would — forming hypotheses about what could go wrong, looking for variants of known CVEs, ranking findings by confidence, and suggesting concrete fixes.

What makes it different from pattern scanners like Semgrep/Snyk/CodeQL:

- Hypothesis-driven scanning: for each function, the scanner generates specific security hypotheses ("this transaction doesn't lock the row — potential race condition") rather than matching a fixed regex library
- Variant analysis: given a known CVE, finds structurally similar code patterns in your codebase
- AI-guided fuzzing: sends payloads, analyzes responses, generates smarter payloads in a feedback loop
- PoC generation: produces concrete exploit scripts that verify vulnerabilities are real, not theoretical
- Multi-agent pipeline: Recon → Hypothesis → Analyzer → Exploit, each stage informs the next

Stack:
- 43 scanner categories (15 production-wired, 28 experimental): code patterns, secrets, deps, IaC, AI/LLM security, API security, cloud misconfig, supply chain, crypto audit, zero trust, privacy/GDPR, GraphQL, WebSocket, JWT, CORS, OAuth, SSTI, session, race conditions, and more
- 329+ built-in rules
- 59 CLI commands
- 8 languages (TypeScript, JavaScript, Python, Go, Java, PHP, C/C++, Rust)
- Works with Claude, GPT-4o, Ollama, or any OpenAI-compatible model — or pattern-only offline without any API key
- SARIF 2.1.0 output for GitHub Code Scanning
- VS Code extension, GitHub Action, MCP server, REST API
- Full OWASP Top 10 coverage

Quick start:
  npx mythos-agent scan        # pattern scan (no API key needed)
  npx mythos-agent hunt        # full AI-powered security hunt
  npx mythos-agent quick       # 10-second security check

GitHub: https://github.com/mythos-agent/mythos-agent

TypeScript, MIT licensed. ~25K lines, 33 test files.

I'd love feedback on the hypothesis-generation approach and what vulnerability categories to prioritize adding next.
```

---

## Twitter / X Thread

### Tweet 1 — Launch
```
🔐 Introducing mythos-agent — open-source AI code reviewer for application security.

Reasons about code instead of just matching patterns.

→ 43 scanner categories
→ 329+ built-in rules
→ Hypothesis-driven scanning
→ CVE variant analysis
→ AI-guided fuzzing with PoC generation

npx mythos-agent scan

github.com/mythos-agent/mythos-agent
```

### Tweet 2 — What Makes It Different
```
What makes mythos-agent different from Semgrep/Snyk/CodeQL?

1️⃣ It REASONS about code, not just matches patterns
2️⃣ It generates hypotheses: "this function could be vulnerable because…"
3️⃣ It finds structural variants of known CVEs
4️⃣ It proves vulnerabilities with concrete PoC exploits
5️⃣ It chains findings into multi-step attack paths
```

### Tweet 3 — Scanner Categories
```
43 scanner categories including:

🤖 AI/LLM Security (prompt injection, cost attacks)
🔑 API Security (OWASP API Top 10)
☁️ Cloud Misconfig (AWS/Azure/GCP)
🔗 Supply Chain (typosquatting, dep confusion)
🔒 Crypto Audit (weak hashes, hardcoded keys)
🛡️ Zero Trust (service auth, mTLS)
🔐 Privacy/GDPR (PII handling, consent)
⚡ Race Conditions (TOCTOU, double-spend)
```

### Tweet 4 — Quick Demo
```
Try it in 10 seconds:

npx mythos-agent quick

Output:
🔐 2.3/10 | 3C 8H 2M (13ms)

  🔴 SQL Injection — src/api.ts:45
  🔴 JWT None Algorithm — src/auth.ts:78
  🔴 Hardcoded Secret — src/config.ts:12

  → mythos-agent fix --severity critical --apply

One command. Instant results.
```

### Tweet 5 — Call to Action
```
mythos-agent is MIT licensed and free forever.

⭐ Star if you want to see more AI-powered security tools
🔧 Contribute: "good first issue" labels are up
📦 npm install -g mythos-agent

github.com/mythos-agent/mythos-agent

Works with Claude, GPT-4o, Ollama — or runs pattern-only offline.
```

---

## Reddit Posts

### r/netsec
```
Title: mythos-agent: open-source AI security scanner — 43 categories, 329+ rules, hypothesis-driven scanning

Open-source AI code reviewer that layers AI reasoning on top of traditional SAST. Combines hypothesis-driven scanning with CVE variant analysis.

Key capabilities:
- Hypothesis-driven scanning: AI generates specific security hypotheses per function
- CVE variant analysis: finds code structurally similar to known vulnerabilities
- AI-guided fuzzing with feedback loop
- PoC exploit generation for confirmed findings
- Multi-agent pipeline: Recon → Hypothesize → Analyze → Exploit

Covers: injection (SQL, NoSQL, command, SSTI), XSS (8 DOM patterns), auth (JWT, OAuth, session), crypto (11 rules), cloud (AWS/Azure/GCP), supply chain, zero trust, privacy/GDPR, GraphQL, WebSocket, and 30+ more categories.

Works with Claude, GPT-4o, or local models (Ollama). Pattern scanning works offline without any API key.

GitHub: https://github.com/mythos-agent/mythos-agent

Feedback welcome — especially from pentesters on what rules/checks are missing.
```

### r/programming
```
Title: I built an open-source AI security scanner with 43 vulnerability categories in TypeScript

mythos-agent is an open-source AI code-review assistant. Instead of matching regex patterns like traditional SAST, it uses AI to reason about what could go wrong in each function — generating specific hypotheses rather than running a fixed rule library.

Some numbers:
- ~25K lines of TypeScript
- 329+ built-in security rules
- 43 scanner categories (15 production-wired, 28 experimental)
- 59 CLI commands
- 33 test files
- Scans: TS, JS, Python, Go, Java, PHP, C/C++, Rust

The most interesting part: the hypothesis agent reads functions and generates security hypotheses like *"this endpoint doesn't validate the user ID — potential IDOR"* rather than matching against a static pattern library.

Try it: npx mythos-agent scan

GitHub: https://github.com/mythos-agent/mythos-agent
```

### r/cybersecurity
```
Title: Open-source AI code reviewer with AI/LLM security scanning, supply chain detection, and zero-trust validation

Releasing mythos-agent — a CLI security tool that combines 43 scanner categories with AI-powered reasoning. Highlights for this community:

- AI/LLM Security: detects prompt injection, unsafe eval of AI output, API key exposure in client code, cost attacks (13 rules)
- Supply Chain: typosquatting detection, dependency confusion, dangerous install scripts
- Zero Trust: implicit service trust, missing mTLS, overprivileged accounts
- Privacy/GDPR: PII logging, missing consent, data retention (mapped to GDPR articles)
- Compliance reports: SOC2, HIPAA, PCI-DSS, OWASP Top 10 mapping
- SARIF 2.1.0 output for GitHub Code Scanning

Also includes a STRIDE threat model generator, security scorecard with letter grades, and secrets rotation guides.

Free, open-source, MIT licensed: https://github.com/mythos-agent/mythos-agent
```

---

## LinkedIn Post

```
🔐 Excited to announce mythos-agent — an open-source AI code-review assistant for application security.

Security scanners mostly match patterns. mythos-agent reasons about code like a security reviewer: it forms hypotheses about what could go wrong in each function, looks for structural variants of known CVEs, and chains findings into multi-step attack paths.

What makes it unique:
→ Hypothesis-driven scanning (AI reasons about what COULD go wrong per function)
→ CVE variant analysis (finds code structurally similar to known vulnerabilities)
→ 43 scanner categories covering OWASP Top 10, supply chain, AI/LLM security, cloud misconfig, zero trust, and more
→ 329+ built-in rules across 8 programming languages
→ Compliance reporting for SOC2, HIPAA, PCI-DSS, OWASP, and GDPR

For security teams:
• Drop-in CI/CD integration (GitHub Action + SARIF 2.1.0)
• Policy-as-code with compliance mapping
• VS Code extension with inline diagnostics
• REST API and MCP server for tool integration

For developers:
• npx mythos-agent quick — 10-second security check
• npx mythos-agent fix --apply — AI-generated patches
• npx mythos-agent ask "find auth bypasses" — natural language queries

Works with Claude, GPT-4o, Ollama, or any OpenAI-compatible model. MIT licensed. Free forever.

🔗 GitHub: https://github.com/mythos-agent/mythos-agent

#cybersecurity #opensource #devsecops #appsec #ai
```

---

## Product Hunt

### Tagline Options
1. "The AI code reviewer that reasons about security bugs — open-source, 329+ rules"
2. "43 security scanners, 329 rules, AI-powered — one npm install"
3. "AI code reviewer that reasons about code like a security researcher"

### Description (260 chars)
```
mythos-agent is an open-source AI code-review assistant with 43 scanner categories and 329+ rules. Unlike pattern matchers, it hypothesizes vulnerabilities, finds CVE variants, generates PoC exploits, and auto-fixes issues. Covers AI/LLM, API, cloud, supply chain, and more.
```

---

## Dev.to / Blog Post Outline

### Title: "Why Pattern-Matching Scanners Miss Structural Bugs (and What We Built Instead)"

1. **Why pattern-matching scanners miss structural bugs** — Semgrep/Snyk are great at known patterns, but bugs come in variants the rulebook hasn't learned yet.
2. **The gap: semantic reasoning vs. regex** — what variant-analysis research (including published work on Google Project Zero's Big Sleep) suggests about structure-aware scanning.
3. **mythos-agent's approach** — hypothesis-driven scanning + variant analysis layered on top of traditional SAST/DAST tools.
4. **Architecture** — multi-agent pipeline: Recon → Hypothesize → Analyze → Exploit.
5. **Demo** — walk through scanning a real project, showing hypothesis output in the terminal.
6. **What's in the box** — 43 scanner categories, 329+ rules, 59 commands, 8 languages.
7. **What's next** — documentation site, more language support, community rule packs.
8. **Try it** — `npx mythos-agent scan`.

---

## Email to Security Newsletters

### Subject
```
Open-source AI code reviewer for application security (43 categories, 329+ rules)
```

### Body
```
Hi [Name],

I'm launching mythos-agent, an open-source AI code-review assistant that layers AI reasoning on top of traditional SAST — 43 scanner categories, 329+ rules, MIT licensed.

What's different from pattern matchers:
- Hypothesis-driven scanning (AI reasons about what could go wrong per function)
- CVE variant analysis (finds structurally similar code)
- AI-guided fuzzing with PoC generation
- AI/LLM security scanner (prompt injection, cost attacks)
- Compliance mapping (SOC2, HIPAA, PCI-DSS, OWASP, GDPR)

Would this be a good fit for [newsletter name]? Happy to provide more details or a demo.

GitHub: https://github.com/mythos-agent/mythos-agent

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

## GitHub Release Notes (v3.1.0)

```markdown
## mythos-agent v3.1.0 — AI Code Reviewer for Application Security

Open-source AI code reviewer that reasons about security bugs instead of just matching patterns.

### Highlights
- 🧪 **Hypothesis-driven scanning** — AI reasons about what could go wrong per function
- 🔬 **CVE variant analysis** — find code structurally similar to known vulnerabilities
- 🤖 **43 scanner categories** — 15 production-wired + 28 experimental — code patterns, AI/LLM security, zero trust, privacy, and more
- 🎯 **329+ built-in rules** across 8 programming languages
- 🛡️ **59 CLI commands** covering scanning, fixing, reporting, compliance, and more
- 📦 **SARIF 2.1.0 output** — drop-in GitHub Code Scanning integration
- 🎨 **First-class brand system** — Cerby the mascot, favicon, social preview (see [BRAND.md](./BRAND.md))

### Backends supported
- Claude (via Anthropic API)
- GPT-4o (via OpenAI API)
- Ollama and any OpenAI-compatible local model
- Offline: pattern scanning works without any API key

### Quick Start
```bash
npm install -g mythos-agent
mythos-agent scan
```

### Full Changelog
See [CHANGELOG.md](./CHANGELOG.md)
```

---

## Launch Day Schedule

**Best day: Tuesday or Wednesday.**
**Best time for Show HN: 6–9 AM US Eastern.**

| Time (ET) | Action |
|---|---|
| T-48h | DM 5–10 dev friends with launch time + post links; ask for engaged comments (not just upvotes) |
| T-24h | Final review of Show HN post; record/polish demo GIF; tag release on GitHub; `npm publish` |
| T-0 (8:00 AM) | Post Show HN |
| T+5 min | Post Twitter/X thread (5 tweets) |
| T+10 min | Post to r/netsec, r/programming, r/cybersecurity (stagger by 5 min each) |
| T+30 min | Post on LinkedIn |
| T+1 h | Submit to Product Hunt (12:01 AM PT the following day is optimal for PH specifically; adjust if you're running separate PH launch) |
| T+1.5 h | Send newsletter outreach emails |
| T+2 h | Post on Dev.to |
| Rolling 0–48h | Monitor HN/Reddit/Twitter, reply to every comment within 15 min |
| T+5 h | Post metrics update in thread (stars, installs, feedback themes) |
| T+1 day | Optional: cross-post to Chinese dev communities (V2EX, Juejin) and relevant Discord servers (OWASP, DevSecOps) |

---

## Response playbook for common comments

| Comment pattern | Response frame |
|---|---|
| *"How is this different from Semgrep?"* | Pattern-matching vs. reasoning. Concrete example: "Semgrep finds `eval(req.body)`; mythos-agent also flags `new Function(userInput)` constructed three calls away via taint flow." |
| *"Does it actually work or is it vaporware?"* | Link to a real scan output on a public repo. Have 2–3 examples pre-staged. |
| *"API key required?"* | No. Pattern + secrets + deps + IaC scanning all work offline. AI reasoning is opt-in. |
| *"What's the false positive rate?"* | Confidence scoring per finding; `--severity high` only shows high-confidence. Share your own data if you've measured. |
| *"License? Can I use this commercially?"* | MIT. Yes. |
| *"How do you compare to [paid commercial tool]?"* | Honest: paid tools have human-curated rulesets and dedicated teams. mythos-agent is a complement — use both, especially in CI. |
| Hostile/trolling | Ignore once; if persistent, "thanks for the feedback, moving on" and disengage. Do not dogpile. |
