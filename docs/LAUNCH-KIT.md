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
- [x] Domain `mythos-agent.com` purchased and live on Vercel (HSTS + CSP + short-URL redirects)
- [x] Landing page shipped — https://mythos-agent.com
- [x] Demo GIF recorded and embedded in README and landing `/#demo`
- [x] GitHub Discussions enabled (Q&A + Ideas categories live)
- [x] Cross-repo domain cleanup merged (PR #25)
- [x] Email forwarders live: `security@mythos-agent.com`, `conduct@mythos-agent.com`

**Remaining before firing Show HN (aim 06:00 ET Wed 2026-04-22):**
- [ ] Merge the `chore(main): release 4.0.0` release-please PR (triggers npm publish + Sigstore + SBOM)
- [ ] Verify `npm view mythos-agent version` returns `4.0.0`
- [ ] Upload `cerby-banner-social.png` at repo Settings → Social preview
- [ ] Upload `web-app-manifest-512x512.png` as GitHub org avatar + npm org avatar
- [ ] Set GitHub repo description: *"AI code reviewer that reasons about security bugs instead of just matching patterns. 43 scanner categories, 329+ rules, 8 languages. MIT licensed."*
- [ ] Set GitHub repo Website field to `https://mythos-agent.com`
- [ ] Add GitHub topics: `security`, `scanner`, `ai`, `sast`, `dast`, `vulnerability`, `owasp`, `cybersecurity`, `cli`, `typescript`, `devsecops`, `appsec`, `llm-security`
- [ ] Pin repo on your GitHub profile
- [ ] Stand up Discord server per `docs/DISCORD-SETUP.md`; paste the discord.gg invite into `mythos-agent-landing/vercel.json`'s `/discord` redirect
- [ ] Create 3–5 `good first issue` labels on real issues
- [ ] Pre-warm 5–10 dev friends via DM 48h before launch (so: Monday 2026-04-20 evening or Tuesday 2026-04-21 morning)

---

## Hacker News Post

### Title (under 80 chars)
```
Show HN: mythos-agent – open-source AI code reviewer for security bugs
```

### Body
```
Demo: https://mythos-agent.com/#demo

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

Landing:   https://mythos-agent.com
GitHub:    https://github.com/mythos-agent/mythos-agent
Community: https://mythos-agent.com/discord

TypeScript, MIT licensed. ~25K lines, 33 test files. Released today as v4.0.0 with Sigstore-signed builds and CycloneDX SBOMs.

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

mythos-agent.com

npx mythos-agent scan
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
mythos-agent is MIT licensed and free forever. v4.0.0 is live on npm today.

⭐ Star if you want to see more AI-powered security tools
🔧 Contribute: "good first issue" labels are up
💬 Join: mythos-agent.com/discord

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

Works with Claude, GPT-4o, or local models (Ollama). Pattern scanning works offline without any API key. Releases are Sigstore-signed with CycloneDX SBOMs attached.

Landing page + demo: https://mythos-agent.com
GitHub: https://github.com/mythos-agent/mythos-agent
Community: https://mythos-agent.com/discord

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

Website: https://mythos-agent.com
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

Free, open-source, MIT licensed.
Website: https://mythos-agent.com
GitHub: https://github.com/mythos-agent/mythos-agent
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

🌐 Website: https://mythos-agent.com
🔗 GitHub:  https://github.com/mythos-agent/mythos-agent
💬 Community: https://mythos-agent.com/discord

#cybersecurity #opensource #devsecops #appsec #ai
```

---

## Product Hunt

### Tagline Options
1. "The AI code reviewer that reasons about security bugs — open-source, 329+ rules"
2. "43 security scanners, 329 rules, AI-powered — one npm install"
3. "AI code reviewer that reasons about code like a security researcher"

### Description (under 260 chars)
```
mythos-agent.com — open-source AI code-review assistant with 43 scanner categories and 329+ rules. Hypothesizes vulnerabilities, finds CVE variants, generates PoC exploits. Works with Claude, GPT-4o, Ollama. MIT, Sigstore-signed.
```

### Gallery (prepare ahead)
1. **Hero screenshot** of mythos-agent.com (1270×760) — shows Cerby + tagline + CTAs
2. **demo.gif** — the 15-second terminal recording (PH allows up to 3 MB; current file is 235 KB, well under)
3. **Trust signals row** screenshot — OpenSSF / Sigstore / SBOM / MIT badges in a single crop
4. Optional: scanner matrix screenshot showing the 23-chip grid
5. Optional: pipeline SVG (Recon → Exploit)

---

## Dev.to / Blog Post Outline

### Title: "Why Pattern-Matching Scanners Miss Structural Bugs (and What We Built Instead)"

1. **Why pattern-matching scanners miss structural bugs** — Semgrep/Snyk are great at known patterns, but bugs come in variants the rulebook hasn't learned yet.
2. **The gap: semantic reasoning vs. regex** — what variant-analysis research (including published work on Google Project Zero's Big Sleep) suggests about structure-aware scanning.
3. **mythos-agent's approach** — hypothesis-driven scanning + variant analysis layered on top of traditional SAST/DAST tools.
3.5. **How the landing page was built** (optional aside) — Astro 6 + Tailwind v4 + Cerby mascot system; 180 KB total payload with zero-JS defaults. Repo: https://github.com/mythos-agent/mythos-agent-landing
4. **Architecture** — multi-agent pipeline: Recon → Hypothesize → Analyze → Exploit.
5. **Demo** — walk through scanning a real project, showing hypothesis output in the terminal.
6. **What's in the box** — 43 scanner categories, 329+ rules, 59 commands, 8 languages.
7. **What's next** — documentation site, more language support, community rule packs.
8. **Try it** — `npx mythos-agent scan` · `mythos-agent.com` · `mythos-agent.com/discord`.

---

## Email to Security Newsletters

### Subject
```
Open-source AI code reviewer for application security (43 categories, 329+ rules)
```

### Body
```
Hi [Name],

I'm launching mythos-agent, an open-source AI code-review assistant that layers AI reasoning on top of traditional SAST — 43 scanner categories, 329+ rules, MIT licensed. v4.0.0 shipped 2026-04-22 with Sigstore-signed builds.

What's different from pattern matchers:
- Hypothesis-driven scanning (AI reasons about what could go wrong per function)
- CVE variant analysis (finds structurally similar code)
- AI-guided fuzzing with PoC generation
- AI/LLM security scanner (prompt injection, cost attacks)
- Compliance mapping (SOC2, HIPAA, PCI-DSS, OWASP, GDPR)

Would this be a good fit for [newsletter name]? Happy to provide more details or a demo.

Website: https://mythos-agent.com
GitHub:  https://github.com/mythos-agent/mythos-agent

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

## GitHub Release Notes (v4.0.0)

```markdown
## mythos-agent v4.0.0 — AI Code Reviewer for Application Security

Open-source AI code reviewer that reasons about security bugs instead of just matching patterns.

Landing: https://mythos-agent.com
Community: https://mythos-agent.com/discord

### Highlights
- 🧪 **Hypothesis-driven scanning** — AI reasons about what could go wrong per function
- 🔬 **CVE variant analysis** — find code structurally similar to known vulnerabilities
- 🤖 **43 scanner categories** — 15 production-wired + 28 experimental — code patterns, AI/LLM security, zero trust, privacy, and more
- 🎯 **329+ built-in rules** across 8 programming languages
- 🛡️ **59 CLI commands** covering scanning, fixing, reporting, compliance, and more
- 📦 **SARIF 2.1.0 output** — drop-in GitHub Code Scanning integration
- 🎨 **First-class brand system** — Cerby the mascot, favicon, social preview (see [BRAND.md](./BRAND.md))
- 🔐 **Sigstore-signed tarball + CycloneDX SBOM** attached to this release

### Breaking changes in v4.0.0
- SBOM `documentNamespace` moved from `sphinx-agent.dev` to `mythos-agent.com` (completes the v3.x rebrand). Downstream consumers parsing the namespace for provenance should update their pinning.
- Security contact email is now `security@mythos-agent.com` (was `security@sphinx-agent.dev`, which never existed).

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

## Launch Day Schedule — 2026-04-22 (Wed)

All times in **US Eastern** with **Beijing** in parens (user's local tz; user awake during this window).

| Time (ET) | Beijing | Action |
|---|---|---|
| **T-48h** (Mon 20, eve) | (Tue 21, AM) | DM 5–10 dev friends with launch time + post links; ask for **engaged comments**, not just upvotes |
| **T-24h** (Tue 21, 06:00) | 18:00 | Final review of Show HN post; merge the v4.0.0 release-please PR; verify `npm view mythos-agent version` → `4.0.0`; push final README + Discord badge commits; sanity-check everything one more time |
| **T-0** 06:00 | 18:00 | **Post Show HN** (first — HN is the hardest and benefits from a quiet window) |
| T+5 min 06:05 | 18:05 | Post Twitter/X thread (5 tweets, thread-reply form) |
| T+10 min 06:10 | 18:10 | Post r/netsec |
| T+15 min 06:15 | 18:15 | Post r/programming |
| T+20 min 06:20 | 18:20 | Post r/cybersecurity |
| T+30 min 06:30 | 18:30 | Post LinkedIn |
| T+1 h 07:00 | 19:00 | Send newsletter outreach emails (tl;dr sec, Console.dev, DevSecOps Weekly, SANS NewsBites, This Week in Security) |
| T+1.5 h 07:30 | 19:30 | Post Dev.to blog |
| T+2 h 08:00 | 20:00 | First metrics check-in reply to the HN thread |
| Rolling 0–18h | 18:00 → 12:00 next day | Monitor HN + Reddit + Twitter; reply to every comment within 15 min when awake |
| **T+18h** 23:59 | 12:59 Thu | Submit Product Hunt (Thursday PH launch — PH day starts midnight PT) |
| T+24h Thu 06:00 | 18:00 Thu | Post a 24h retrospective reply in the HN thread: stars, installs, top feedback themes |
| T+48h Fri | | Optional cross-post to V2EX / Juejin / OWASP Discord / DevSecOps Discord |

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
| *"Do you have a Discord?"* | Yes — `mythos-agent.com/discord`. `#help` for questions, `#rule-ideas` for scanner proposals. |
| *"Is the project funded? Who pays you?"* | Unpaid individual maintainer; GitHub Sponsors is the one way to support today: `mythos-agent.com/sponsor`. Planning to apply to Open Source Collective + Sovereign Tech Fund — see `ROADMAP.md`. |
| Hostile/trolling | Ignore once; if persistent, "thanks for the feedback, moving on" and disengage. Do not dogpile. |
