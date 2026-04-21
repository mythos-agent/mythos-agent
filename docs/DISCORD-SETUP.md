# Discord Server Setup

Step-by-step to stand up the `mythos-agent` Discord server and have it feel intentional on day one. ~30 min of clicking, all free, done once.

Everything below is **paste-ready**: copy the fenced blocks directly into the Discord UI. Placeholder tokens like `<REPLACE_WITH_SERVER_ID>` are called out explicitly.

---

## 0. Why Discord

Every mainstream OSS dev-tool launch in the last three years runs on Discord: Bun, Astro, tRPC, Prisma, Linear's community, Turborepo. It's where the target audience already is. GitHub Discussions is the async/asynchronous record; Discord is where someone types "anyone else seeing this error" and gets an answer in four minutes. Both, not either-or.

---

## 1. Create the server

1. **https://discord.com** → log in with the maintainer account → left sidebar → **`+` Add a server** → **Create My Own** → **For a club or community**.
2. **Server name:** `mythos-agent`
3. **Icon:** upload `assets/cerby-chip.svg` converted to a 512×512 PNG. (Discord will not accept SVG here.)
4. Click **Create**.

You're now the Owner of an empty server.

## 2. Set Community features

These unlock the Rules channel, Announcements channels, welcome screen, and server insights.

1. **Server Settings → Enable Community → Get Started**
2. Skip the rules and guidelines screens for now — you'll set them from the pasted content below
3. Finish the wizard

## 3. Rebuild the channel list

Delete the default `# general` voice + text channels that Discord creates, then paste this tree by hand. Discord doesn't support channel import, so this is manual.

```
📣 INFO  (category)
   # welcome           (text)  — read-only for @everyone, maintainer posts only
   # announcements     (announcement channel)  — maintainer posts only
   # github-activity   (text)  — webhook feed, no human posting

💬 COMMUNITY  (category)
   # general
   # help
   # show-and-tell

🛠 CONTRIBUTE  (category)
   # contributors
   # rule-ideas
```

**Permissions per category:**

- `INFO` — `@everyone`: View only. `@Maintainer`: post everywhere. `@Bot`: post in `# github-activity` only.
- `COMMUNITY` — `@everyone`: read + send messages + add reactions + use threads. No `@everyone` mention allowed.
- `CONTRIBUTE` — same as COMMUNITY but also require verification level Medium.

## 4. Roles

Server Settings → Roles → create these, in this order (ordering matters for permission hierarchy):

| Role | Color (hex) | Permissions |
|---|---|---|
| `Maintainer` | `#5B2A86` (brand violet) | Administrator |
| `Contributor` | `#22D3EE` (brand cyan) | Manage Messages in their own threads, nothing admin |
| `Pioneer` | `#A78BFA` (soft violet) | Same as Contributor + cosmetic |
| `Bot` | `#6B7280` | Send Messages, Embed Links; nothing else |
| `@everyone` | — | Send Messages, Add Reactions, Use Threads; **cannot @mention roles or @everyone** |

Keep roles minimal at launch. Add `Moderator`, `Sponsor`, etc. after there's actual activity.

## 5. Server settings

Server Settings → fill in:

- **Safety Setup** → Verification Level: **Medium** (verified email + account > 5 min old)
- **Safety Setup** → Explicit Content Filter: **Scan messages from all members**
- **Moderation** → **2FA Requirement for Moderation: ON**
- **Server Insights**: toggle ON (needed for launch-day member growth metrics)
- **Default Notifications**: Only @mentions (keeps `# general` chatter from pinging everyone)

## 6. Bots

### 6a. Carl-bot (moderation + welcome DMs)

1. `https://carl.gg` → **Invite** → pick the `mythos-agent` server → grant the default permissions
2. Back in the server, use `?welcome` to open the welcome setup, then paste the Welcome DM template from §8 below
3. `?autorole add @Contributor` — optional; leave off at launch (promote manually after first PR merges)
4. `?automod spam on` — anti-raid and anti-spam
5. `?prefix ?` — default; leave it

### 6b. GitHub webhook (release/PR/issue feed)

1. Discord: `# github-activity` channel → ⚙ Edit Channel → **Integrations** → **Webhooks** → **New Webhook** → name it `GitHub` → **Copy Webhook URL**
2. GitHub: `github.com/mythos-agent/mythos-agent/settings/hooks` → **Add webhook** → paste the URL **with `/github` appended to the end** (this activates Discord's GitHub-aware formatter) → Content type: `application/json` → Events:
   - Pull requests
   - Issues
   - Issue comments
   - Releases
   - Pushes (branch `main` only — set via "Let me select individual events")
   - Discussions
   - Stars *(optional; emits for each new star — noisy past ~50 stars/day, mute if needed)*
3. Click **Add webhook**. GitHub sends a test ping; confirm it appears in `# github-activity` within 10 s.

## 7. Permanent invite link + `mythos-agent.com/discord`

1. `mythos-agent` server → right-click → **Invite People** → **Edit invite link** → set **Expire After: Never**, **Max Number of Uses: No limit** → Generate Link
2. Copy the full `https://discord.gg/XXXX` URL
3. In the `mythos-agent-landing` repo: open `vercel.json` and replace the placeholder in the `/discord` redirect entry with this URL (a PR/commit has already been pushed wiring everything else; only this destination is blank)
4. `git commit -am "feat(redirect): wire /discord to live server"` → `git push`
5. Verify: `curl -sI https://mythos-agent.com/discord | head -2` → `HTTP/1.1 307` + `Location: https://discord.gg/XXXX`

Now every mention of `mythos-agent.com/discord` anywhere (README badge, SUPPORT, LAUNCH-KIT, Footer, issue templates) routes to this invite, and you can rotate the invite later without changing any public docs.

---

## 8. Paste-ready content

### `# welcome` pinned message

Post once as the Owner, then pin it. Plain Markdown; Discord renders it.

```markdown
# Welcome to mythos-agent 👋

**mythos-agent** is an open-source AI code reviewer for application security.
43 scanner categories · 329+ built-in rules · MIT licensed.

🔗 **Landing:** https://mythos-agent.com
🐙 **GitHub:** https://github.com/mythos-agent/mythos-agent
📦 **npm:** https://www.npmjs.com/package/mythos-agent

## Where should I ask?

| Question | Channel |
|---|---|
| Quick "how do I…" | **#help** |
| Feature ideas, architecture, scanner proposals | **#rule-ideas** or GitHub Discussions → Ideas |
| Bug reports with reproducers | GitHub Issues |
| Security vulnerabilities — DO NOT POST HERE | security@mythos-agent.com (PGP in SECURITY.md) |
| Code of Conduct concerns | conduct@mythos-agent.com |

## Read before you post

- **#rules** — six short lines, please skim
- **SECURITY.md** — never disclose vulnerabilities in public channels; use private reporting
- **CODE_OF_CONDUCT.md** — Contributor Covenant, enforced by the maintainer

Say hi in **#general** — we want to know what brought you here.
```

### `# rules` channel content (or welcome-screen "Guidelines")

```markdown
**Server rules**

1. **Be respectful.** The Contributor Covenant applies. One warning, then a ban.
2. **No zero-day disclosure in public.** If you think you've found a vulnerability, use security@mythos-agent.com or GitHub's private advisory. Posting it here puts users at risk.
3. **Keep scanner false-positive discussions in #help** with a minimal reproducer; move to a GitHub issue if it's a real bug.
4. **No self-promo without context.** Sharing *your* OSS project is fine if it's genuinely relevant to the thread. Dumping links is not.
5. **Use threads for multi-message conversations.** Keeps channels scannable.
6. **English is the primary channel language** so everyone can follow. Other languages welcome in DMs and side channels if we add them later.

Ban policy: two warnings for minor issues; immediate ban for doxxing, harassment, or exploit peddling.
```

### Channel topics (one line each — set via Edit Channel → Topic)

```
# welcome         — Start here. Pinned: how to use the server + where to ask what.
# announcements   — Releases, breaking changes, launch updates. Maintainer only.
# github-activity — Auto-posted PRs, issues, releases. No human posting.
# general         — Intro, off-topic, casual chat.
# help            — "How do I…" questions. One thread per question, please.
# show-and-tell   — Findings you made with mythos-agent, custom rule packs, integrations.
# contributors    — PR review chatter, scanner SDK, roadmap discussion.
# rule-ideas      — Propose new scanner rules before opening an issue or PR.
```

### Carl-bot welcome DM (sent to each new joiner)

Paste into Carl-bot's `?welcome` editor. `{user}` is a Carl-bot variable.

```
Hey {user} 👋 welcome to **mythos-agent**.

Three quick links to get you oriented:

🔗 Landing: https://mythos-agent.com
📖 GitHub: https://github.com/mythos-agent/mythos-agent
❓ Ask anything in **#help**

If you're here because of the launch — the demo at mythos-agent.com/#demo is the 30-second version. If you're here for something specific, drop a line in #general and someone will point you the right way.
```

### `# announcements` launch-day post (paste at 06:00 ET on 2026-04-22)

```markdown
**mythos-agent v4.0.0 is live 🚀**

After months of building in the open, the AI code reviewer that reasons about security bugs (instead of matching patterns) is officially launched.

- 🔗 https://mythos-agent.com
- 📦 `npx mythos-agent scan`
- 🐙 https://github.com/mythos-agent/mythos-agent
- 📝 Show HN post: <link will be edited in at T+5 min>
- 🐦 Twitter thread: <link at T+10 min>

Say hi in **#general**, ask anything in **#help**, and if you want to help it grow — a GitHub star is worth more than a retweet.

Thanks to everyone who pre-warmed this launch. You know who you are. 💜
```

---

## 9. Post-setup verification

Before firing the Show HN post, run this list:

1. `https://mythos-agent.com/discord` opens the `mythos-agent` invite in an incognito browser
2. Join the server anonymously → welcome DM arrives within 30 s → auto-role applies (if configured)
3. Push a trivial commit to sphinx-agent → `# github-activity` shows it within a minute
4. `# welcome` message is pinned; `# rules` content is present; all channel topics set
5. `# announcements` is set as an Announcement channel (check via channel settings → "Enable Announcement")
6. Server Insights page in Server Settings shows "Data collection: enabled"
7. README.md Discord shield in the repo shows an online-member count (requires the server ID — find it via Server Settings → Widget → Server ID — and paste into the shield URL template in README)

---

## 10. What to add *after* launch, not before

Resist the urge to build this out pre-launch. These are justified by real usage:

- Voice channel for office hours (when there's reliable attendance)
- `#sponsors` private channel (when there are sponsors)
- `#maintainers` private channel (when there's more than one)
- Language-specific channels (`#cn`, `#ja`) (when there's clear demand)
- Event scheduling for CVE retrospectives / hack nights (after 100+ active members)

The smallest server that answers questions quickly beats the biggest server that looks busy.
