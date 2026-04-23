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

### ⚠ Reddit pre-launch prerequisites (read before any reddit post)

These apply to all three subreddits below. Failing any of these dramatically raises the chance of silent AutoMod removal or ban.

1. **Contributor Quality Score (CQS).** Reddit computes an internal trust score per account (Lowest / Low / Moderate / High / Highest). Thousands of subreddits — including the three below — run AutoMod with `contributor_quality: < moderate` to silently remove posts from low-trust accounts. If `[your reddit account]` is brand new or has mostly self-promo history, it is likely Low/Lowest and your launch posts will be auto-removed before a human mod sees them. CQS is driven primarily by upvoted **comments** on other people's posts, not your own posts. Build it in the week before launch by leaving 10–20 substantive comments across general tech subreddits (r/ExperiencedDevs, r/programming, r/netsec, r/cybersecurity). Check your current CQS at `reddit.com/settings` → "Contributor quality score" (if visible).

2. **90/10 rule (site-wide).** Reddit's guideline is that ≤10% of your total posts+comments should be self-promotion. A fresh account posting only launch content = 100% self-promo = spam by definition. If your account has nothing in the "90" bucket, spend the T-1h window making at least 6–10 technically substantive comments on existing threads in the subreddits you plan to post in (and use the same account you'll post from).

3. **Crossposting cadence.** Dumping identical launch content into r/netsec + r/programming + r/cybersecurity within a 10-minute window is a known spam pattern that both Reddit's site-wide AutoMod and individual subreddit AutoMod rules detect. The schedule in this document originally had them 5 min apart; it has been **re-spaced to ≥30 min between subreddits** and each post **uses a different title, a different angle, and a different body** (do not reuse). If you shortcut this and paste the same thing to all three, expect removals.

4. **Subreddit-specific gates.** Each of the three sections below has its own "Compliance gate" note. Do not skip those.

5. **r/programming April 2026 LLM ban is still in effect.** r/programming announced a temporary ban on LLM-related content starting April 1, 2026 as a 2–4 week trial. Your launch lands Wed 2026-04-22, inside that window and possibly after an extension. Read the r/programming section below carefully — the risk of your post being removed as "LLM content" is high.

---

### r/netsec

**⚠ Compliance gate — read before posting.** r/netsec is aggressively moderated. The subreddit explicitly rejects "tool posts without technical explanation" and flags curated-list framing (numeric counts in titles). To have any chance of staying up, this post must read as a **technical essay on a scanning approach**, not a product announcement. Specifically:

1. **The Dev.to technical writeup must be published BEFORE this post**, and it must be the primary link. Landing page, GitHub, and Discord are tertiary at best — Discord link removed entirely below because it reads as commercial self-promo.
2. **Account history matters.** If `[your reddit account]` has never commented on r/netsec before, the mods will likely read this as commercial cold-posting and remove + ban. Before launch day, spend ~30 min making 2–3 technically substantive comments on existing r/netsec threads so the account has prior-engagement signal.
3. **If the Dev.to writeup slips past launch day, skip r/netsec entirely** and use the subreddit's monthly discussion/tool thread instead (pinned at the top of the subreddit). Posting the product announcement as a standalone link will fail the "tool posts without technical explanation" rule.

```
Title: Layering LLM-generated hypotheses on a traditional SAST pipeline: what structure-aware variant analysis catches that regex rulesets miss

Write-up: <LINK TO DEV.TO POST — must be live before posting this>

Pattern-matching scanners like Semgrep, Snyk, and CodeQL find what their rulebook encodes. Bugs that come in structural variants the rulebook hasn't seen — or that only manifest after taint-following a user-controlled value across three function boundaries — slip through. The technical question this tool set out to answer: can an LLM-based hypothesis stage, layered on top of a traditional SAST foundation, usefully surface those gaps without drowning the signal in false positives?

Approach:

(1) Hypothesis generation per function. A traditional AST parser extracts functions; an LLM agent is prompted per-function to produce specific security hypotheses — "this DB transaction reads and writes the same row without locking; potential TOCTOU race"; "this handler joins a user-supplied path against a config root without resolving symlinks; potential path traversal." Hypotheses are concrete claims about *this* code, not generic CWE labels.

(2) Analyzer stage grades each hypothesis. A separate agent reads the function and decides whether the claim actually holds given the code shape — inputs, sinks, control flow, error paths. Confidence scoring is per-finding, so `--severity high` shows only high-confidence output.

(3) Structural variant analysis. Given a reference CVE (from NVD or a user-supplied patch), the scanner searches the codebase for AST-shape-similar regions with semantic-role matching on inputs/sinks. Similar in spirit to what Google Project Zero described in the public Big Sleep write-up, applied to an open-source TypeScript toolchain.

(4) Optional exploit stage. For confirmed findings, a PoC agent produces a concrete script that exercises the vulnerability — a proof that it is real rather than theoretical.

Pipeline: Recon → Hypothesize → Analyze → Exploit. Each stage feeds the next; Exploit is optional and off by default.

The tool also runs in pattern-only mode (no LLM, no API key) as a fallback / offline mode; in that mode it is a conventional rule-based scanner. The hypothesis and variant stages are the parts worth technical discussion.

Full write-up in the link above. Open source under MIT. Backends: Claude, GPT-4o, Ollama, or any OpenAI-compatible endpoint. Releases are Sigstore-signed with CycloneDX SBOMs.

Questions I'd value technical feedback on:
- Where has per-function hypothesis generation produced the most noise for you in similar systems, and what mitigations worked?
- For structure-aware variant analysis on dynamically-typed languages (Python, JS), what's your experience with AST-shape normalization to get useful similarity scores?

Source: https://github.com/mythos-agent/mythos-agent
```

### r/programming

**⚠ Compliance gate — this is the highest-risk subreddit on your list.** Three reasons:

1. **Active LLM content ban (April 2026).** r/programming started a 2–4 week trial ban on LLM-related content on April 1, 2026. Your launch is April 22 — inside the trial window, and the mods have signalled the ban may become permanent. The previous draft of this post led with "AI security scanner" in the title and emphasised AI reasoning throughout the body — that framing will almost certainly be removed under the ban. Mods have said "technical breakdowns on machine learning are still allowed" but "new model announcements, ChatGPT tutorials, and 'will AI replace me?' threads" are out. A tool post where the headline feature is LLM-powered reasoning is closer to the banned bucket than the allowed one.
2. **Numeric-count titles.** Curated-list framing ("43 categories, 329+ rules", "8 languages") is the same pattern r/netsec's rulebook explicitly discourages; r/programming is similar in tone.
3. **90/10 rule.** r/programming has 6.9M members and is mod-heavy. Posts from accounts with no prior engagement get pulled quickly.

**Recommendation:** unless you (a) have a real prior r/programming track record AND (b) are willing to rewrite the post to lead with the **static-analysis tooling / TypeScript build** angle and bury the LLM/AI framing, **skip r/programming this launch cycle.** Wait until the ban is explicitly lifted (watch their pinned announcement post), then submit a technical deep-dive write-up instead of a product announcement.

If you want to post anyway, below is a reframed version that minimises LLM exposure and leads with the non-AI aspects of the toolchain. Even this version is not guaranteed to survive the ban — post it as a calculated bet, not an expectation.

```
Title: Building a TypeScript static-analysis toolchain on top of Babel's AST: 43 scanner categories, SARIF 2.1.0 output, 8 target languages

Short technical write-up on the structure of an open-source static-analysis toolchain I've been working on (mythos-agent, MIT-licensed). Focus here is on the scanner architecture and the language-parser layer, not on any individual scan category.

Parser layer: uses Babel's parser for TS/JS (native), and delegates to language-specific parsers via a small adapter interface for the other 7 targets (Python via tree-sitter, Go via go/ast bindings, Java via JavaParser via subprocess, PHP via PHP-Parser via subprocess, Rust via tree-sitter, C/C++ via tree-sitter). Adapter interface yields a normalized CST shape with per-node source-range metadata so rule authors don't have to rewrite their matching logic per language.

Rule representation: each of the 329 built-in rules is a pattern + a matcher against the normalized CST, plus a confidence prior and a CWE/OWASP mapping. Rules compose — a "SQL injection" rule is actually N smaller rules (string concatenation into a sink, template literal with untrusted interpolation, query-builder with raw-SQL escape hatch, etc.). This makes adding a new variant cheaper than adding a new top-level rule.

Output surface: SARIF 2.1.0 for GitHub Code Scanning drop-in, HTML reports with a deterministic CSS layout, JSON for piping into other tooling. SARIF output validates against the 2.1.0 schema in CI via ajv.

Supply chain scanning runs separately from the AST layer (different problem shape — you're inspecting `package.json` and `package-lock.json` rather than source). Typosquatting detection uses a Levenshtein distance against the top-10k npm packages list, with false-positive suppression for known-intentional namespaces (@types/*, @aws-sdk/*, etc.).

Packaging: single npm package, `npx mythos-agent scan` entry point. ~25K LOC, 33 test files, 59 CLI subcommands. Releases are Sigstore-signed (cosign) with CycloneDX SBOMs attached to GitHub releases.

Specifically interested in feedback on:
- Multi-language AST normalization: where does the adapter pattern break down? Anyone tried this and regretted it?
- SARIF 2.1.0 consumers beyond GitHub Code Scanning — which tools actually render SARIF well, and which silently drop half the fields?

Source (MIT): https://github.com/mythos-agent/mythos-agent
```

Notes on the reframed version:
- Title leads with "TypeScript static-analysis toolchain" — concrete, non-AI, non-list.
- Body does not mention LLMs, hypothesis generation, variant analysis, or AI agents at all. Those features exist but are not the story here.
- Ends with two specific technical questions — signals that you want discussion, not upvotes.
- One link at the bottom, source only. No landing page, no Discord.
- If a commenter asks "does it use AI?" in the thread, answer factually and briefly in a reply — that's allowed. Leading the post with AI is what triggers the ban.

### r/cybersecurity

**⚠ Compliance gate — read before posting.** r/cybersecurity enforces two rules that the original draft below violates:

1. **Rule 5 (No advertising) — flair is mandatory for launches.** Any educational post that references a tool you built must be flaired **"Corporate Blog"** at submission time. Reddit's submit form lets you pick a flair before clicking Post; do not skip this. Do **not** solicit DMs, calls, or private contact in the post — mods treat that as circumvention and ban immediately.
2. **Rule 6 (No excessive promotion) — 10% cap.** Self-promotion (any link to your own project) must be under 10% of your total r/cybersecurity activity, and once per week max per promoted entity. If `[your reddit account]` has 0 prior r/cybersecurity posts/comments, a single launch post is 100% self-promo → **auto-violates Rule 6**. Fix the same way as r/netsec: make 2–3 technically substantive comments on existing r/cybersecurity threads in the T-1h window before launch. Use the same account you'll post from.
3. **If you don't qualify** (no prior account history AND no time to build it) → **skip r/cybersecurity entirely.** r/netsec + r/programming are enough reddit coverage for launch day. Posting into a rule violation gets you banned, losing the subreddit for all future launches.

Also: r/cybersecurity mods often remove cross-posted launch content when they see the same user post identical framing in r/netsec / r/programming within minutes. The version below is intentionally framed differently from the r/netsec post.

**Submit-form settings:**
- **Flair:** `Corporate Blog` (set at submission time — cannot skip, per Rule 5)
- **Title** (paste exactly, under 300 chars): `Scanning for LLM-introduced bugs: four patterns I codified while building an open-source code reviewer`
- **Body type:** Text post, markdown mode (new Reddit: toggle "Markdown Editor" in the bottom-right; old.reddit.com: just paste)
- **Body:** paste everything inside the fenced block below (do NOT paste the outer fence itself)

````markdown
Short writeup on a category of bugs that classical SAST tooling mostly doesn't touch: issues introduced by LLM-generated or LLM-integrated code. While building an open-source code reviewer ([mythos-agent](https://github.com/mythos-agent/mythos-agent), MIT), this category kept surfacing and didn't map cleanly onto existing rulesets. Sharing the patterns in case they're useful, and because I'm curious what other defenders are seeing in the same space.

## 1. Prompt injection reaching downstream logic

**Pattern.** User input flows into a system prompt, chat history, or tool-call argument without boundary enforcement.

```js
// common in client-side LLM apps
const history = [
  { role: 'system', content: 'You are a helpful assistant.' },
  { role: 'user',   content: req.body.message },   // unchecked
];
const reply = await llm.chat(history);
if (reply.tool_calls?.[0]?.name === 'send_email') {
  sendEmail(reply.tool_calls[0].arguments);        // attacker-controllable
}
```

If the attacker gets the model to emit `tool_calls[0].name = 'send_email'` with attacker-chosen arguments, the downstream `sendEmail` executes. Traditional SAST sees no taint flow — the sink is reached via the *model's output*, not the user's input directly.

**Mitigation that survives audit.** Tool-call allowlisting + argument schema validation + human-in-the-loop for destructive tools (send email, run shell, transfer funds).

## 2. Unsafe eval of LLM output

**Pattern.** `eval`, `Function`, `exec`, `subprocess.*(shell=True)`, `vm.runInNewContext`, `importlib.import_module`, etc., fed with model output.

```python
# "let the model generate a small helper function"
code = llm.chat("Write a Python function that ...").content
exec(code)                                         # shell game over
```

Model providers (OpenAI, Anthropic) document "don't eval model output" explicitly. Teams ship this anyway because the happy-path demo works.

**Mitigation.** Run generated code in an isolated sandbox (firejail, gVisor, Wasm, Docker with seccomp), with no network and a writable-only scratch volume. If sandboxing is too heavy, `ast.parse` + whitelist-walk the AST before execution.

## 3. API key exposure in client code

**Pattern.** Provider keys baked into shipped JS bundles, browser extensions, or mobile apps.

```ts
// Vite / Next.js public env var — shipped to the browser
const client = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_KEY });
```

If the key is readable to the browser, it's readable to the attacker. Unauthenticated attackers then drain the quota overnight. Any client-side key with billing attached is a pending incident.

**Mitigation.** Proxy the provider call through your own backend; attach your own auth + rate limit; keep the provider key server-side only.

## 4. Cost attacks on unauthenticated paid-model endpoints

**Pattern.** A public endpoint invokes a paid model on arbitrary input, with no rate limit, no `max_tokens` cap, no auth.

```ts
app.post('/summarise', async (req, res) => {
  const out = await claude.messages.create({
    model: 'claude-opus',
    max_tokens: 4096,
    messages: [{ role: 'user', content: req.body.text }],
  });
  res.json(out);
});
```

Not a confidentiality bug. A **billing DoS**. A single attacker script can run up five-figure charges before anyone notices. Scanner rulebooks built around the CIA triad miss this entirely.

**Mitigation.** Auth on every model-invoking endpoint. Per-user and per-IP rate limit. Hard `max_tokens` cap. Daily spend ceiling at the provider level (most providers expose this — set it).

---

## Adjacent categories I didn't expect to need first-class rules for

- **Supply chain**: typosquatted npm packages targeting AI libraries specifically (`openai-client`, `anthropic-sdk`, etc. — enough real squats now that this needs dedicated detection). Post-install scripts in LLM-related deps.
- **Zero-trust failures between services**: implicit service-to-service trust where "our API → model provider → our API" is assumed safe without re-authenticating the return path.
- **Privacy / GDPR**: PII from user prompts logged verbatim to stdout / observability platforms, with no redaction layer. Tracking consent often bypassed for "AI improvement" features.

## Question for the thread

What bug classes are you seeing in LLM-integrated codebases that the four patterns above don't cover? I'm particularly interested in patterns that show up *after* a codebase has hardened against prompt injection — what the "second wave" of issues looks like.

Source (MIT): https://github.com/mythos-agent/mythos-agent
````

**Why this framing survives Rule 5 / Rule 6:**
- Title leads with the bug class, not the tool. The tool is named once in parens at the top and once as the source link at the bottom.
- Four concrete code examples (one per bug class) — evidence-based, not marketing prose. This is the single biggest rule-survival signal.
- Each pattern has a named mitigation, so the post has standalone educational value even if the reader never clicks the source link.
- Zero "Website:" / "GitHub:" / "Community:" triple-link block — that pattern mirrors ad-copy and is exactly what Rule 5 enforcement tends to hit.
- Single discussion-seeking question at the end, not a call-to-action.
- Do **not** solicit DMs, calls, or private contact anywhere in the post — mods treat that as Rule 5 circumvention and ban immediately.

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

### Tagline Options (PH 60-char limit — all fit)
1. `Open-source AI cybersecurity agent — 329+ rules, MIT` *(52 chars, recommended)*
2. `AI cybersecurity agent that reasons, not just matches` *(53 chars)*
3. `AI cybersecurity agent — 43 scanners, SARIF 2.1.0, OSS` *(54 chars)*

### Description (under 260 chars)
```
mythos-agent.com — open-source AI cybersecurity agent with 43 scanner categories and 329+ rules. Hypothesizes vulnerabilities, finds CVE variants, generates PoC exploits. Works with Claude, GPT-4o, Ollama. MIT, Sigstore-signed.
```

### Gallery (prepare ahead)
1. **Hero screenshot** of mythos-agent.com (1270×760) — shows Cerby + tagline + CTAs
2. **demo.gif** — the 15-second terminal recording (PH allows up to 3 MB; current file is 235 KB, well under)
3. **Trust signals row** screenshot — OpenSSF / Sigstore / SBOM / MIT badges in a single crop
4. Optional: scanner matrix screenshot showing the 23-chip grid
5. Optional: pipeline SVG (Recon → Exploit)

### Submission form — field-by-field

| PH form field | Value to paste |
|---|---|
| **Website** | `https://mythos-agent.com` |
| **Source** (GitHub repo) | `https://github.com/mythos-agent/mythos-agent` |
| **Discord** (community link) | `https://mythos-agent.com/discord` |
| **Twitter / X** | your launch-thread URL (posted at T+5) |

Product Hunt doesn't have a dedicated Feishu field — include the Feishu invite in the maker's first comment (next subsection).

### Maker's first comment (post immediately after the launch goes live on PH)

````markdown
Hey PH 👋 maker here.

Try it in 10 seconds, no API key needed:

```bash
npx mythos-agent scan
```

If you hit a false positive, open an issue with a minimal repro — that's the feedback I need most.

[GitHub (MIT)](https://github.com/mythos-agent/mythos-agent) · [Write-up](<DEV.TO LINK>) · [Discord](https://mythos-agent.com/discord) · [Feishu](https://mythos-agent.com/feishu)

Happy to answer anything in the thread 🙏
````

---

## Dev.to Post (paste-ready)

Publish at **T−15 min** (Wed 2026-04-22, 05:45 ET). The URL must be live before the r/netsec post at T+30, which links to this writeup as its primary reference.

**Editor settings:**
- Toggle **Editor → Markdown mode** (top-right of the Dev.to editor). Frontmatter is parsed automatically and does not render in the final article.
- Before first publish, replace `<your-username>/<this-slug>` in `canonical_url` with what Dev.to assigns after you save the first draft. (Save once, copy the URL from the browser address bar, paste into frontmatter, save again.)
- Tags: exactly 4 (Dev.to max). Current choice: `security, opensource, ai, typescript` — swap `typescript` for `javascript` or `devsecops` if either draws a bigger audience that week.

````markdown
---
title: "Why Pattern-Matching Scanners Miss Structural Bugs (and What I Built Instead)"
published: true
description: A technical writeup on layering LLM-generated hypotheses on top of a traditional SAST pipeline, with concrete examples of bugs that regex rulesets miss and structural variant analysis catches.
tags: security, opensource, ai, typescript
cover_image: https://mythos-agent.com/og.png
canonical_url: https://dev.to/<your-username>/<this-slug>
---

## TL;DR

Pattern-matching scanners (Semgrep, Snyk, CodeQL) find what their rulebook encodes. Bugs that arrive as **structural variants** — the sink is three calls away, the taint flows through an unusual shape, the CVE matters but the pattern doesn't match verbatim — slip through.

I built **mythos-agent**, an open-source AI code reviewer (MIT, TypeScript, [GitHub](https://github.com/mythos-agent/mythos-agent)), to layer an LLM-based hypothesis stage on top of a traditional SAST foundation. This post is the technical writeup: what the pipeline looks like, what bug classes it surfaces that regex-only scanners miss, and where it still gets things wrong.

```bash
npx mythos-agent scan     # pattern scan, no API key
npx mythos-agent hunt     # full AI hypothesis + analyzer pipeline
```

---

## 1. The problem: rulebook coverage vs. bug space

A pattern scanner's ruleset is a finite set of `(sink, source, condition)` triples. A security reviewer reading the same code carries a much larger implicit model — they notice that *this* DB transaction reads and writes the same row without locking, that *this* handler joins a user-supplied path against a config root without resolving symlinks, that *this* `eval` receives a value that's been stringified three functions upstream.

Concrete example. Semgrep's default TypeScript ruleset catches this:

```ts
app.get('/run', (req, res) => {
  eval(req.query.code);           // flagged: eval() on request input
});
```

It does **not** catch this, even though it's the same bug:

```ts
function normalise(input: unknown) {
  return String(input).trim();
}

function buildPayload(raw: string) {
  return normalise(raw);
}

app.get('/run', (req, res) => {
  const payload = buildPayload(req.query.code as string);
  new Function(payload)();        // not flagged: sink ≠ eval, source is 2 calls away
});
```

The pattern rule is looking for `eval(<tainted>)` literally. The real bug is `<any dynamic-code sink>(<tainted, possibly transformed, possibly renamed>)`. You can write a Semgrep rule for this variant — but you can only write rules for variants you've already thought of. The space of "things that behave like eval" is open-ended.

---

## 2. The approach: hypothesis generation per function

The mythos-agent pipeline is four stages:

```
Recon → Hypothesize → Analyze → Exploit (optional)
```

The interesting stage is **Hypothesize**. For each function the parser extracts, a prompted LLM agent produces specific, code-grounded security claims — not CWE labels, but statements about *this* code:

> "This handler reads `req.query.path` and passes it to `fs.readFileSync` via `path.join(ROOT, userPath)` without resolving symlinks. Potential path traversal if the filesystem contains symlinks pointing outside `ROOT`."

> "This transaction reads `balance` at line 42 and writes `balance - amount` at line 51, without wrapping in `SELECT … FOR UPDATE` or an equivalent lock. Potential TOCTOU race allowing double-spend under concurrent requests."

The hypotheses are inputs to the next stage, not outputs to the user.

---

## 3. The analyzer: grading hypotheses against the code

A separate analyzer agent re-reads the function with the hypothesis attached and decides whether the claim actually holds given the control flow, input reachability, and sink characteristics. Findings get a confidence score in `[0, 1]`; `--severity high` only surfaces results above a threshold.

This two-stage split matters. The hypothesis stage is allowed to be speculative — it's cheap to generate a hypothesis that turns out to be wrong, and the analyzer will filter it. The analyzer stage is allowed to be conservative. Running them together in a single prompt collapses the useful separation: the model both proposes and evaluates, and in practice that means it emits plausibility-matched false positives.

Example output (real, from scanning a test corpus):

```
 ✗ src/api/transfer.ts:38   [HIGH, conf 0.88]
   Hypothesis: read-modify-write of `balance` without row lock;
               concurrent requests can double-spend.
   Evidence:   line 42 reads `balance`, line 51 writes `balance - amount`;
               no FOR UPDATE / transaction isolation in scope.
   Suggested:  wrap in BEGIN ... SELECT ... FOR UPDATE ... COMMIT,
               or use SERIALIZABLE isolation level.
```

---

## 4. Structural variant analysis

Given a reference CVE (from NVD, or a user-supplied patch), the variant analyzer searches the codebase for AST-shape-similar regions with semantic-role matching on inputs/sinks. Similar in spirit to what Google Project Zero described in the public **Big Sleep** writeup, applied to an open-source TypeScript toolchain.

The use case this actually solves: *"we patched bug X in module A; are there other places in the codebase that look like module A before the patch?"* Regex search over `git diff` misses these because the variant can rename the variables, reorder the statements, split a helper out, etc.

---

## 5. What's in the box

- **43 scanner categories** (15 production-wired, 28 experimental): SQL injection, SSRF, path traversal, command injection, XSS, JWT algorithm confusion, session handling, race conditions, crypto audit, secrets, IaC misconfig, supply chain, AI/LLM security, API security, cloud misconfig, zero trust, privacy/GDPR, GraphQL, WebSocket, CORS, OAuth, SSTI, and more.
- **329+ built-in rules** across **8 languages** (TypeScript, JavaScript, Python, Go, Java, PHP, C/C++, Rust). Rules compose — "SQL injection" is N smaller rules, not one regex.
- **Output**: SARIF 2.1.0 (drop-in for GitHub Code Scanning), HTML reports, JSON for piping.
- **Backends**: Claude, GPT-4o, Ollama, or any OpenAI-compatible endpoint. **Pattern-only mode works offline without any API key** — the hypothesis stage is opt-in.
- **Releases are Sigstore-signed** (cosign) with CycloneDX SBOMs attached to each GitHub release.

---

## 6. Where it still gets things wrong

Hypothesis-driven scanning is not free. Honest limits:

- **Dynamically-typed languages** (Python, JS) produce more noise than statically-typed ones. Type information is a signal the analyzer leans on heavily; without it, confidence scores drift lower and the high-severity filter leaves more on the floor.
- **Inter-procedural taint across package boundaries** still loses signal. If the tainted value crosses into a third-party dep with no source, the hypothesis stage has to reason about the dep's public surface, and it often over-generates.
- **Cost**. Running the hypothesis stage across a 100k-LOC codebase with Claude or GPT-4o is not free. The `--severity high` filter helps; incremental scans on changed files help more. CI integration should scope to diff-only by default.

---

## 7. Try it

One command, no install, no API key needed for pattern-only mode:

```bash
npx mythos-agent quick       # 10-second security check
npx mythos-agent scan        # full pattern scan
npx mythos-agent hunt        # AI-guided scan (needs a model endpoint)
npx mythos-agent fix --apply # AI-generated patches for high-confidence findings
```

- **GitHub**: https://github.com/mythos-agent/mythos-agent
- **Landing / docs**: https://mythos-agent.com
- **Community (EN)**: https://mythos-agent.com/discord
- **Community (CN · 飞书)**: https://mythos-agent.com/feishu
- **Releases**: Sigstore-signed, SBOM attached

MIT licensed. v4.0.0 shipped today. If you have a codebase you'd want tested against hypothesis generation (public or a redacted snippet), open an issue or a discussion — I'm specifically looking for cases where the analyzer produces unexpected false positives, since those are the most useful signal for tuning the prompt.

## Questions I'd value technical feedback on

1. For **per-function hypothesis generation**, where has the "speculate then analyze" split produced the most noise in systems you've built or used?
2. For **structural variant analysis on dynamically-typed languages**, what's your experience with AST-shape normalisation to get useful similarity scores across Python or JS?
3. Which **SARIF 2.1.0 consumers beyond GitHub Code Scanning** actually render SARIF well, and which silently drop half the fields?

Thanks for reading. Star on GitHub if this is useful; open an issue if you find a bug.
````

**Why this structure works for Dev.to:**
- TL;DR up top with the elevator pitch + tool link + runnable command — if someone bounces after the first paragraph, they still have what they need.
- Concrete "Semgrep catches X, misses Y" code example in §1 is the specific evidence for the whole thesis. Anyone who doesn't read past §1 still sees the value prop backed up.
- Honest-limits section (§6) is what differentiates a technical writeup from a product announcement. Security readers trust authors who name their own tool's weaknesses.
- Call-to-action in §7 is specific ("find false positives, open an issue") rather than generic ("star please").
- Closing questions are open-ended and technical — signals discussion-seeking, which Dev.to's comment algorithm rewards.

---

## V2EX Post (Chinese, paste-ready)

Publish at **T+48h** on Fri 2026-04-24 in the Beijing-evening window (**20:00–22:00 UTC+8** = 08:00–10:00 ET Friday). V2EX readers are skeptical of AI-hype; this post leads with the technical problem, shows real output early, and names limits honestly — the tone V2EX credits.

**Submit-form settings:**
- **节点 (Node):** `分享创造` (https://www.v2ex.com/go/create) — the correct node for individual-developer OSS launches. Do **not** post to `推广` (/go/promotions) — that's for paid / commercial promotion and the node choice itself reads as wrong intent.
- **标题 (Title)** — user-chosen title (option 3). Alternatives kept below for reference.
  1. `做了个开源的 AI 代码安全智能体 mythos-agent，想在 V 站求轻拍` *(recommended — matches `mythos-agent` naming, uses 2026 Chinese AI-industry standard term 智能体)*
  2. `[分享创造] mythos-agent —— 给传统 SAST 加一层 LLM 假设生成的开源代码安全智能体`
  3. `[开源] mythos-agent v4.0.0：不止于模式匹配的 AI 代码安全智能体`
- **正文 (Body):** paste the markdown block below (do NOT paste the outer fence). V2EX supports Markdown natively — fenced code blocks, headings, links, bold all render.

````markdown
大家好，分享一个最近折腾的开源项目：**mythos-agent** —— 一个 AI 驱动的代码安全智能体。

- GitHub：https://github.com/mythos-agent/mythos-agent
- 主页：https://mythos-agent.com
- 飞书群：https://mythos-agent.com/feishu
- Discord：https://mythos-agent.com/discord
- 协议：MIT

简单说下为什么做这个，以及怎么跑。

## 起点

Semgrep / Snyk / CodeQL 这类扫描器用多了，会发现一个很现实的问题：它们能找到的漏洞，基本就是规则库里写过的那些。规则库覆盖不到的结构变体 —— 比如 `eval` 不是直接作用在 `req.body` 上，而是中间过了两层函数、变量名被改了 —— 基本就漏掉了。

做一段时间代码审计之后，我意识到人在读这类代码时其实是在**提假设**：

> "这里 `path.join` 拼了用户传的 path，但没解析 symlink，是不是路径穿越？"
> "这里对同一行先读后写，没加锁，是不是 TOCTOU 竞态？"

传统规则匹配做不到这一步，但 LLM 可以。mythos-agent 做的就是这件事：**在传统 AST 扫描之上，加一层 LLM 假设生成 + 验证**。不是用 LLM 替代规则库，是给规则库补一个"大胆假设、小心求证"的 stage。

## 三条命令先跑起来

```bash
npx mythos-agent scan        # 纯规则扫描，不需要 API key，完全离线
npx mythos-agent hunt        # 完整 AI 假设 + 验证流水线（需要 LLM 端点）
npx mythos-agent quick       # 10 秒快速体检
```

典型输出：

```
 ✗ src/api/transfer.ts:38   [HIGH, conf 0.88]
   Hypothesis: 对 balance 的读-改-写没加行锁，并发请求可能双花。
   Evidence:   line 42 读 balance，line 51 写 balance - amount；
               作用域内没有 FOR UPDATE / 事务隔离。
   Suggested:  BEGIN ... SELECT ... FOR UPDATE ... COMMIT，
               或 SERIALIZABLE 隔离级别。
```

## 架构

四个阶段：`Recon → Hypothesize → Analyze → Exploit`（Exploit 默认关闭）。

关键是 **Hypothesize 和 Analyze 分成两个 agent**。Hypothesize 阶段让模型"大胆假设"——允许它对每个函数产出很多不一定成立的具体猜测；Analyze 阶段让另一个 agent 逐条去验证，带置信度打分。两步合成一个 prompt 会退化成"模型既出题又打分"，实际结果是生成一堆看起来合理但实际不存在的 false positive。

分成两个 agent 之后，`--severity high` 这种阈值过滤才真的有意义。

## 技术选型

- TypeScript 写的，TS/JS 用 Babel 解析器，其他语言（Python、Go、Java、PHP、Rust、C/C++）走各自的 parser 适配器，统一到一个 normalized CST
- 43 个扫描分类（15 个正式上线，28 个实验中）：SQL 注入、SSRF、路径穿越、命令注入、XSS、JWT 算法混淆、竞态、加密误用、AI/LLM 安全（prompt injection、cost attack）、供应链（typosquatting）、零信任、隐私/GDPR 等
- 329+ 条内置规则，8 种目标语言
- 后端支持 Claude、GPT-4o、Ollama，以及任意 OpenAI 兼容端点；**纯规则模式完全离线，不需要任何 API key**
- 输出 SARIF 2.1.0（GitHub Code Scanning 直接能用）、HTML 报告、JSON
- 发布产物用 Sigstore (cosign) 签名，附带 CycloneDX SBOM

## 目前的坑 (说实话)

- **动态类型语言** (Python、JS) 的 false positive 比静态类型语言多。类型信息是 Analyze 阶段的重要信号，没有的话整体置信度偏低。
- **跨第三方依赖的污点追踪会丢信号**。污点流进一个没源码的 dep，假设阶段只能按 public API 推测，容易过度生成。
- **成本**。全仓跑假设生成用 Claude / GPT-4o 一次不便宜，CI 里建议只跑 diff。

## 适合谁用

- 平时写 TypeScript / Node.js 后端，想给 CI 加一层 SAST 又不想买商业扫描器
- 给 LLM 集成类项目做安全审查（prompt injection / 客户端 API key 泄漏 / 未鉴权的付费模型调用这几类传统 SAST 基本覆盖不到）
- 对 SAST + LLM 的结合方式感兴趣，想看看一个开源实现长什么样

## 最后

MIT 协议，v4.0.0 今天刚发。欢迎拍砖，特别想听几个方向的反馈：

1. 假设生成这套路子，你们有没有踩过类似的坑？哪些假设类型特别容易翻车？
2. 对动态类型语言的 AST 归一化，有什么经验？
3. SARIF 2.1.0 除了 GitHub Code Scanning，还有哪些下游消费者真的能把字段完整渲染出来？

如果有 bug 或者 false positive 例子，直接开 issue，最好附一小段能复现的代码片段。谢谢各位。
````

**Why this structure works on V2EX:**
- Title is concrete with a `[分享创造]` prefix and names the key mechanism (LLM 假设). No `重磅` / `全新一代` / `革命性` hype words.
- `大家好` + `折腾` opening is conversational and slightly self-deprecating — the tone V2EX credits over corporate framing.
- "起点" section names the *problem* before naming the tool; reframes the post as "let's discuss this technical question" rather than "let me show you my product."
- Three `npx` commands appear before architecture so readers can try it in 10 seconds — V2EX rewards 先跑起来 over 先讲故事.
- Real terminal output from `transfer.ts` is the strongest evidence that the tool works.
- "目前的坑 (说实话)" section pre-empts the top three comment threads V2EX would otherwise open. Honest limits convert skeptics.
- Closing is three open technical questions, not a "star please" call-to-action. No Discord / LinkedIn / Twitter cross-links — those read as commercial channel-building on V2EX.
- ~1,100 Chinese characters, mobile-readable in one scroll.

---

## Other Chinese Communities (beyond V2EX)

Four platforms across Tier 1 (do these) and Tier 2 (do if bandwidth). Total effort ≈ 3 hours spread over a week. No new drafts — reuse existing V2EX body and Dev.to article.

### Tier 1 — high-signal

#### 1. 掘金 (Juejin) — https://juejin.cn
- **Audience**: ~15M Chinese devs; long-form technical content; Baidu-indexed
- **Format**: Full article, Markdown. Editor UI fields: 标题, 分类 (选 后端 or AI), 标签 (3–5), 封面图 (use `https://mythos-agent.com/og.png`)
- **Recommended tags**: pick 3–5 from `AI编程`, `安全`, `开源`, `TypeScript`, `静态分析`
- **分类 (category)**: `后端` — `AI` 分类的流量高但以大模型本体 / 应用层为主，`后端` 的读者对 SAST / AST / CI 这类工具更对口
- **Submit**: log in to juejin.cn → click `写文章` (top-right)
- **Timing**: T+72h (Sat 2026-04-25, 20:00–22:00 Beijing)

##### 标题选项（3 选 1，都在掘金 SEO 甜点区 25–40 字）
1. `传统 SAST 漏掉的结构性 bug，和一个开源尝试：给代码扫描器加一层 LLM 假设生成` *（推荐 —— 问题 + 方案明确，搜索词齐全）*
2. `从 Semgrep 漏掉的一类 bug 说起：在开源 SAST 工具里加一层 LLM 假设生成的思路`
3. `开源 AI 代码安全智能体 mythos-agent：设计、实现、以及坑`

##### 正文（paste-ready）

````markdown
## TL;DR

模式匹配扫描器（Semgrep / Snyk / CodeQL）能找出规则库里写过的漏洞，但很多真实 bug 是**结构变体** —— sink 和 source 之间隔了三层函数、污点被重命名过、CVE 的 pattern 稍微换了个马甲 —— 这种就漏了。

**mythos-agent** 是一个开源的 AI 代码安全智能体（MIT, TypeScript, [GitHub](https://github.com/mythos-agent/mythos-agent)），思路是在传统 SAST 之上加一层**基于 LLM 的假设生成** stage，用"大胆假设、小心求证"去补规则库覆盖不到的盲区。

这篇文章聊一下这套 pipeline 是怎么设计的、能抓到哪些规则扫描器抓不到的 bug、以及**哪些场景下它依然会翻车**（这部分在第六章，想先看的话直接跳过去）。

```bash
npx mythos-agent scan     # 纯规则扫描，不需要 API key
npx mythos-agent hunt     # 完整 AI 假设 + 验证流水线
```

---

## 一、为什么传统扫描器会漏掉结构变体

pattern 扫描器的规则集本质上是一组有限的 `(sink, source, condition)` 三元组。但人做代码审计时用的心智模型比这大得多 —— 人会注意到**这个**事务对同一行先读后写没加锁、**这个** handler 把用户传的路径拼到 config root 上但没解析 symlink、**这个** eval 接受了从三个函数外 stringify 过来的值。

举个具体例子。Semgrep 默认的 TypeScript 规则集能抓这个：

```ts
app.get('/run', (req, res) => {
  eval(req.query.code);           // 会被标记：eval() 接受了请求输入
});
```

但抓不到下面这个，虽然这俩本质是同一个 bug：

```ts
function normalise(input: unknown) {
  return String(input).trim();
}

function buildPayload(raw: string) {
  return normalise(raw);
}

app.get('/run', (req, res) => {
  const payload = buildPayload(req.query.code as string);
  new Function(payload)();        // 抓不到：sink 不是 eval，source 在两层函数外
});
```

规则在找的是字面的 `eval(<污点>)`。真实的 bug 其实是 `<任意动态执行 sink>(<污点，可能已变形，可能已改名>)`。你当然可以再写一条 Semgrep 规则覆盖这个变体 —— 但你**只能为已经想到的变体写规则**。「和 eval 行为类似的 sink」这个集合是开放的，枚举不完。

---

## 二、思路：让 LLM 给每个函数"提假设"

mythos-agent 的 pipeline 分四个阶段：

```
Recon → Hypothesize → Analyze → Exploit（默认关闭）
```

最有意思的阶段是 **Hypothesize**。对 parser 抽出来的每个函数，一个带特定 prompt 的 LLM agent 会产出**针对这段代码**的、具体的安全假设 —— 不是给一个笼统的 CWE 标签，而是对**这个**函数作出具体声明：

> "这个 handler 读了 `req.query.path` 并通过 `path.join(ROOT, userPath)` 传给 `fs.readFileSync`，但没解析 symlink。如果文件系统里有指向 ROOT 外的 symlink，可能是路径穿越。"

> "这个事务在第 42 行读 `balance`，在第 51 行写 `balance - amount`，没有包在 `SELECT … FOR UPDATE` 或等价的锁里。并发请求下可能 TOCTOU 竞态导致双花。"

这些假设**不是给用户看的输出**，而是下一个阶段的输入。

---

## 三、Analyze 阶段：给假设打分

另一个 analyzer agent 会带着前一阶段生成的假设重新读这段函数，根据控制流、输入可达性、sink 特征判断假设是否真的成立。每条 finding 带一个 `[0, 1]` 的置信度；`--severity high` 只输出置信度超过阈值的结果。

**两个阶段分开非常重要。** Hypothesize 阶段允许"大胆猜"，允许它产出大量不一定成立的假设 —— 生成假设的成本很低，analyzer 会帮着筛。Analyze 阶段反过来，允许它保守。

把这两步合成一个 prompt 会退化成"模型既出题又打分"，实测的结果就是输出一堆**看起来合理但其实不存在**的 FP。拆成两个 agent 之后，`--severity high` 这种阈值过滤才真的有意义。

实际输出样例（在一个测试仓库上跑出来的）：

```
 ✗ src/api/transfer.ts:38   [HIGH, conf 0.88]
   Hypothesis: 对 balance 的读-改-写没加行锁，并发请求下可能双花。
   Evidence:   line 42 读 balance，line 51 写 balance - amount；
               作用域内没有 FOR UPDATE / 事务隔离。
   Suggested:  BEGIN ... SELECT ... FOR UPDATE ... COMMIT，
               或 SERIALIZABLE 隔离级别。
```

---

## 四、Structural Variant Analysis：找 CVE 的"亲戚"

给定一个参考 CVE（从 NVD 或者用户提供的 patch），variant analyzer 会在目标代码库里搜 **AST 形态相似**的代码块，再对输入和 sink 做语义角色匹配。思路跟 Google Project Zero 公开的 **Big Sleep** writeup 里描述的那套类似，只不过是在一个开源 TypeScript 工具链里实现。

这个功能真正解决的场景是：「A 模块里的 X bug 我们已经 patch 掉了，代码库里还有没有长得像 patch 前 A 模块的地方？」在 `git diff` 上跑 regex 发现不了，因为变体可以改变量名、换语句顺序、拆 helper 函数出去。

---

## 五、目前是什么样

- **43 个扫描分类**（15 个正式上线，28 个实验中）：SQL 注入、SSRF、路径穿越、命令注入、XSS、JWT 算法混淆、session 处理、竞态、加密误用、secrets、IaC 配置错误、供应链、AI/LLM 安全、API 安全、云配置、零信任、隐私/GDPR、GraphQL、WebSocket、CORS、OAuth、SSTI 等
- **329+ 条内置规则**，覆盖 **8 种目标语言**（TypeScript、JavaScript、Python、Go、Java、PHP、C/C++、Rust）。规则是可组合的 —— "SQL 注入"不是一条 regex，而是 N 条更小的规则（字符串拼接到 sink、带污点插值的 template literal、带 raw-SQL escape hatch 的 query builder 等）
- **输出**：SARIF 2.1.0（GitHub Code Scanning 直接能用）、HTML 报告、JSON（可以管道给下游工具）
- **后端**：Claude、GPT-4o、Ollama，以及任意 OpenAI 兼容的端点。**纯规则模式完全离线**，不需要任何 API key —— Hypothesize stage 是可选的，按需开启
- **发布产物**用 Sigstore (cosign) 签名，每次 release 都附带 CycloneDX SBOM

---

## 六、坦白讲，还有这些坑没填好

假设驱动的扫描不是免费午餐，以下是已知的局限：

- **动态类型语言**（Python、JS）比静态类型语言 FP 多。类型信息是 analyzer 阶段的重要信号，没有的话置信度整体偏低，高置信阈值过滤掉的东西也更多。
- **跨第三方依赖的污点追踪会丢信号**。污点流进了一个没源码的 dep，Hypothesize 阶段只能按 public API 推测，容易过度生成。
- **成本**。全仓跑假设生成，用 Claude 或 GPT-4o 一次不便宜。`--severity high` 过滤有帮助；增量扫描（只扫改动过的文件）帮助更大。建议 CI 里 scope to diff-only。

---

## 七、三条命令先跑起来

最低门槛，不装不配置，不需要 API key（pattern-only 模式）：

```bash
npx mythos-agent quick       # 10 秒快速体检
npx mythos-agent scan        # 完整规则扫描
npx mythos-agent hunt        # AI 假设 + 验证（需要 LLM 端点）
npx mythos-agent fix --apply # 对高置信 finding 自动生成并应用 patch
```

- **GitHub**：https://github.com/mythos-agent/mythos-agent
- **主页 / 文档**：https://mythos-agent.com
- **飞书群**：https://mythos-agent.com/feishu
- **Discord**：https://mythos-agent.com/discord
- **发布产物**：Sigstore 签名，附带 SBOM

MIT 协议，v4.0.0 今天刚发。如果你手头有想测试假设生成的代码库（公开的或脱敏过的片段都行），欢迎开 issue —— 我特别想收集 **analyzer 产出的意外 FP 例子**，这是目前微调 prompt 最有用的反馈。

---

## 最后 —— 几个真想听你意见的问题

1. "先出假设再验证"这套两阶段路子，你们在类似系统里有没有踩过坑？哪些假设类型特别容易翻车？
2. 对动态类型语言的 AST-shape 归一化，你们有什么经验？有没有方法能在 Python / JS 上稳定地算 structural similarity？
3. SARIF 2.1.0 除了 GitHub Code Scanning，你们见过哪些下游消费者能把字段完整渲染出来？哪些会 silently 吞字段？

谢谢阅读。觉得有用的话 star 一下；发现 bug 或 FP 请带最小复现开 issue。
````

**Why this version works on 掘金:**
- ~2,500 Chinese chars — 掘金 sweet spot for technical deep-dives (V2EX's 1,100 would read thin here)
- 七章分明的目录结构 —— 掘金 侧边栏会自动生成目录，读者能跳读
- TL;DR 里直接给 `npx` 命令 —— 与 Dev.to 版本一致，降低门槛
- 中英混排保留 `SAST / AST / LLM / Semgrep / SARIF / TOCTOU` 等已经是中文语境标准词的术语；中文标点 + 英文/代码前后加空格
- 第六章"坦白讲，还有这些坑"是差异化关键 —— 掘金 读者对"只吹不黑"的技术文章警惕性很高，提前说 FP、成本、第三方依赖三大坑能建立可信度
- 结尾三个具体技术问题 —— 掘金 算法对"引发讨论"的文章加权，比"求 star"的闭环 CTA 有效

#### 2. HelloGitHub — https://hellogithub.com
- **Audience**: ~500K WeChat subscribers + monthly PDF periodical + web feed. Highest-ROI single channel in CN for OSS launches — accepted projects typically see 1–3K stars in 48h after the monthly issue drops.
- **Format**: Submission **form**, not a post. You cannot paste V2EX / 掘金 / Dev.to content directly — HelloGitHub entries are one-sentence taglines + one short paragraph, not articles.
- **Submit**: https://hellogithub.com/periodical/submit (account required)
- **Timing**: T+24h (Thu 2026-04-23) — monthly issue drops **the 28th** of each month. Submitting by the 26th gives a shot at the April 28 issue; missing it rolls to May 28.
- **Effort**: LOW — ~20 min to fill the form.

##### 表单字段对照（paste-ready）

| 表单字段 | 填什么 |
|---|---|
| **项目名称** | `mythos-agent` |
| **GitHub URL** | `https://github.com/mythos-agent/mythos-agent` |
| **项目分类** | `开发工具` *(如果当月 开发工具 分类已经很满，次选 `人工智能`)* |
| **一句话简介** (≤ 40 CN chars) | `给传统 SAST 加一层 LLM 假设生成的开源代码安全智能体` *(26 chars)* |
| **推荐理由 / 详细介绍** (150–300 CN chars) | 见下方 —— 主版本 ~230 chars，另附两个更短的备用版 |

##### 推荐理由 —— 主版本（≈230 CN chars，推荐）

```
mythos-agent 是一个开源的代码安全扫描工具，思路是在传统 SAST 规则库之上加一层基于 LLM 的假设生成 stage。规则扫描器只能找到规则库里写过的漏洞，漏掉结构变体 —— sink 和 source 之间隔了几层函数、污点被重命名、CVE 的 pattern 稍微换了个马甲，这些都抓不到。mythos-agent 用"先让模型大胆假设，再让另一个 agent 逐条验证"的两阶段路子去补这些盲区。覆盖 8 种语言、43 个扫描分类、329+ 条内置规则，支持 Claude / GPT-4o / Ollama，纯规则模式完全离线不需要 API key。MIT 协议，v4.0.0 刚发。
```

##### 备用版（如果表单字段长度卡得更紧）

**~120 CN chars 版：**

```
mythos-agent 在传统 SAST 规则库之上加了一层 LLM 假设生成 stage，用"先大胆假设、再逐条验证"的两阶段路子去补规则扫描器漏掉的结构变体 bug。覆盖 8 种语言、43 个扫描分类、329+ 条规则，支持 Claude/GPT-4o/Ollama，纯规则模式完全离线。MIT 协议。
```

**~60 CN chars 版（如果字段严格限制）：**

```
在传统 SAST 之上加一层 LLM 假设生成 + 验证的开源代码安全智能体。8 种语言、43 个扫描分类、329+ 条规则，MIT 协议。
```

##### Why this content works for HelloGitHub

- **一句话简介** leads with the *mechanism* (SAST + LLM 假设), not the project name — HelloGitHub's taglines explain what it *does*, not what it's *called*
- **推荐理由** follows a three-beat structure: problem (规则库漏结构变体) → approach (两阶段假设) → surface area (8 语言 / 43 分类 / 329 规则). This matches how 削微寒 edits entries in accepted issues
- Technical terms stay in English (SAST, LLM, sink, source, CVE, MIT) — HelloGitHub's audience is technical; fully-translated versions read as translated-from-English
- **No links inside the 推荐理由** — GitHub URL is a separate field; embedding links in prose looks amateurish
- **No hype words** (`先进 / 颠覆 / 革命性`) — 削微寒 edits these out of accepted entries and may bounce submissions that lean on them

### Tier 2 — lower priority but still worth it

#### 3. SegmentFault 思否 — https://segmentfault.com
- **Audience**: ~3M devs, slightly more enterprise-leaning than 掘金. Security content has a dedicated sub-community.
- **Content to reuse**: cross-post the 掘金 article **verbatim**. Add a one-line canonical note at the bottom: `本文首发于 掘金：https://juejin.cn/post/<id>`
- **Submit**: log in to segmentfault.com → `发布` → `文章`
- **Timing**: T+5d (Mon 2026-04-27) — delay after 掘金 to avoid same-day cross-post pattern
- **Effort**: LOW if the 掘金 article already exists.

#### 4. OSCHINA 开源中国 (软件更新 feed) — https://www.oschina.net
- **Audience**: declining vs. 2018 peak but still Baidu-indexed; 软件更新 feed is a dedicated OSS release channel.
- **Format**: Short news blurb (~200 Chinese chars): product name, version, one-line description, 3–5 key features, repo URL.
- **Submit**: https://www.oschina.net/news/submit (requires account; category = 软件更新)
- **Timing**: T+24h (Thu 2026-04-23) — parallel to HelloGitHub. Different audiences; no overlap risk.
- **Effort**: LOW — ~20 min.

### Platforms we're deliberately skipping and why

| Platform | Reason to skip |
|---|---|
| **CSDN** | SEO-spam site; posts look like content-farm output, low engagement, hurts brand in the CN dev community |
| **博客园 cnblogs** | Older .NET-leaning enterprise audience, declining activity |
| **微博 Weibo** | Mass-consumer social; hashtag discovery for technical content doesn't work without existing followers |
| **B站 Bilibili** | Video platform; would need a custom 3–5 min demo video |
| **InfoQ 中文** | Editorial submission with multi-week lead time; better for post-launch case studies |
| **少数派 SSPai** | Consumer / power-user audience; weak fit for a CLI SAST tool |
| **即刻 Jike** | Short-form social; tech corner too small for ROI |

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
| **T-1h** (Wed 22, 05:00) | 17:00 | Spend ~30 min making 2–3 technically substantive comments on existing r/netsec threads — prior-engagement signal so the mods don't flag the launch post as cold commercial self-promo |
| **T-15 min** 05:45 | 17:45 | **Publish Dev.to blog post** (earlier than HN; the URL must be live so r/netsec can link to it). No traffic on Dev.to at this hour; this does not "leak" the launch |
| **T-0** 06:00 | 18:00 | **Post Show HN** (first — HN is the hardest and benefits from a quiet window) |
| T+5 min 06:05 | 18:05 | Post Twitter/X thread (5 tweets, thread-reply form) |
| T+15 min 06:15 | 18:15 | Post LinkedIn (does not overlap with subreddit AutoMod pattern-detection) |
| T+30 min 06:30 | 18:30 | Post r/netsec **— include the Dev.to link as the primary "Write-up" reference**; if the Dev.to post is not live or account has no r/netsec history, skip and use their monthly discussion/tool thread |
| T+1 h 07:00 | 19:00 | Post r/cybersecurity **with "Corporate Blog" flair** (only if account passes the 10% rule — otherwise skip); send newsletter outreach emails in parallel (tl;dr sec, Console.dev, DevSecOps Weekly, SANS NewsBites, This Week in Security) |
| T+1.5 h 07:30 | 19:30 | **Post r/programming ONLY if LLM ban is confirmed lifted** (check their pinned announcement post first). Otherwise skip. Use the reframed "TypeScript static-analysis toolchain" draft, not the AI-forward one. |
| T+2 h 08:00 | 20:00 | First metrics check-in reply to the HN thread |
| Rolling 0–18h | 18:00 → 12:00 next day | Monitor HN + Reddit + Twitter; reply to every comment within 15 min when awake |
| **T+18h** 23:59 | 12:59 Thu | Submit Product Hunt (Thursday PH launch — PH day starts midnight PT) |
| T+24h Thu 06:00 | 18:00 Thu | Post a 24h retrospective reply in the HN thread: stars, installs, top feedback themes |
| T+24h Thu | Thu afternoon Beijing | **Submit to HelloGitHub** (https://hellogithub.com/periodical/submit) — goal: catch April 28 monthly issue. **Submit to OSCHINA 软件更新** (https://www.oschina.net/news/submit) in parallel. ~40 min total. |
| T+48h Fri | Fri 20:00 Beijing | **V2EX post** (节点 `分享创造` /go/create, Fri 20:00–22:00 Beijing = 08:00–10:00 ET Fri) |
| T+72h Sat | Sat 20:00 Beijing | **掘金 (Juejin) article** — translate the Dev.to article to Chinese, publish with tags `AI编程 / 安全 / 开源 / TypeScript / 静态分析`. ~2h translation effort. |
| T+5d Mon | Mon 20:00 Beijing | **SegmentFault cross-post** — paste the 掘金 article verbatim with a `本文首发于 掘金：<URL>` canonical line at the bottom. ~15 min. |

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
