# Feishu (飞书) Community Setup

Stand up the mythos-agent 中文社区 on Feishu. Parallel to `docs/DISCORD-SETUP.md` — same paste-ready structure, same "route through `mythos-agent.com/<name>` so the invite URL can rotate without touching docs" approach.

Feishu was chosen over WeChat for the Chinese community because:

- **Clickable, non-expiring join link** — no 7-day QR rotation
- **Official GitHub bot** — can post PRs/releases/issues to a group channel the same way Discord's `#github-activity` feed does
- **Searchable message history** — answer a question once, send a link
- **5,000-member group cap** without splitting
- **Professional tool feel** — matches mythos-agent's researcher-grade positioning better than WeChat's casual-messenger vibe
- Target audience (security engineers, DevSecOps, AppSec at mid-to-large CN tech companies) already uses Feishu daily

WeChat remains a viable fallback if indie / hobbyist reach becomes a bottleneck post-launch — easy to add via the soft-demand signal in the 社区 section.

---

## 1. Create the group (~3 min, requires your existing Feishu account)

1. Open Feishu desktop → top-left **+** → **Create group** / **发起群聊**
2. Pick any 2 contacts to start (Feishu requires at least 3 members to form a group; you can remove them after or just have them stay as silent partners).
3. Rename:
   - **Group name**: `mythos-agent 中文社区`
   - **Group description**: `开源 AI 代码审阅工具 mythos-agent 的中文交流群。GitHub · mythos-agent.com`
4. Upload group avatar: use `assets/cerby-chip.svg` → export to 512×512 PNG first (Feishu won't accept SVG). Same source as the Discord server icon.

## 2. Enable external-member / open-link join (~2 min)

Feishu groups default to "tenant members only". For a community group where anyone can join via link, you need to open it up.

Group header → ⚙ **Settings** / **设置** → adjust:

- **允许外部人员进群** / *Allow external members* → **开启** (ON)
- **群聊通过链接加入** / *Join via group link* → **开启** (ON); copy the link that appears
- **入群管理员审批** / *Require admin approval to join* → **关闭** (OFF) for public community — if you keep it on, you're doing manual approval for every new member, which will kill growth
- **仅群主 / 管理员可邀请** / *Only owner/admin can invite* → **关闭** (OFF) so members can bring friends
- **群公告** / *Group announcement* → set to the welcome content from §5 below (pinned at top of group automatically)

## 3. Channel / topic structure

Feishu groups are flat by default — no channel sub-division like Discord. Two options:

**Option A — Single group, use topics / 话题 (recommended for launch)**
- One group, every conversation happens in it
- Use Feishu's **Pin message** / **置顶** feature to keep the top 3–5 reference messages visible
- Scale to 500–1000 members before you need Option B

**Option B — Group + sub-topic groups later**
- When the main group gets noisy, create topic-specific side groups:
  - `mythos-agent 贡献者群` (for merged-PR contributors, invite-only)
  - `mythos-agent 规则讨论群` (scanner rule proposals)
- Keep the main group as the front door

Start with Option A on day 1.

## 4. Bot integrations

### 4a. GitHub activity feed bot

Feishu has first-party GitHub support via custom webhooks — comparable to Discord's built-in GitHub integration.

1. Group → ⚙ **Settings** → **Group bots** / **群机器人** → **Add bot** → **Custom bot** / **自定义机器人**
2. Name the bot: `GitHub`
3. Icon: use `assets/cerby-chip.svg` as 256×256 PNG
4. Click **Add** — you'll get a webhook URL like `https://open.feishu.cn/open-apis/bot/v2/hook/xxxxx`
5. GitHub's webhook format doesn't map 1:1 to Feishu's, so use the community relay `github-webhook-to-feishu` or self-host a tiny function on Vercel / Cloudflare Workers that transforms the payload. Link and sample code: see `docs/integrations/feishu-github-relay.md` (to be added in a follow-up PR — not blocking launch).
6. For launch day, skip the relay and just post manually when PRs / releases land. The bot is a nice-to-have, not a blocker.

### 4b. Anti-spam / auto-welcome (optional, post-launch)

Feishu has native **入群欢迎语** (new-member welcome) that works without a bot. Group → ⚙ Settings → **入群欢迎语** → enable → paste the welcome DM from §5.4.

For anti-spam, Feishu's built-in content filters are decent — unlike WeChat, you don't need 3rd-party bots that risk account bans.

## 5. Paste-ready content

### 5.1 Group announcement (pinned at the top)

Paste into Settings → 群公告 / Group announcement. This is the first thing every new member sees.

```markdown
欢迎来到 mythos-agent 中文社区 👋

mythos-agent 是面向应用安全的开源 AI 代码审阅工具。
43 个扫描器分类 · 329+ 内置规则 · MIT 许可

🔗 官网: https://mythos-agent.com
🐙 GitHub: https://github.com/mythos-agent/mythos-agent
📖 中文 README: https://github.com/mythos-agent/mythos-agent/blob/main/README.zh-CN.md
💬 国际社区 (Discord): https://mythos-agent.com/discord

如何提问:
• 使用方面的快速问题 → 直接在群里问
• 代码片段 → 贴 GitHub gist 链接,不要在群里刷屏
• 规则建议 → GitHub Discussions / Ideas 分类
• 漏洞披露 → 邮件 security@mythos-agent.com,切勿在群内公开讨论

群规:
1. 保持专业尊重 —— 行为准则同 CODE_OF_CONDUCT.md
2. 禁止在群内披露 0day / 未公开漏洞
3. 禁止广告、招聘信息、政治话题
4. 代码讨论请用 gist / GitHub 链接,避免大段粘贴
5. 较长的一对一讨论请开私聊
6. 中英文皆可;技术术语保留英文
```

### 5.2 Rules message (pinned separately, if announcement gets long)

Same six rules as above — can be posted as a separate pinned message if you want explicit visibility.

### 5.3 Welcome message on join

Feishu Settings → **入群欢迎语** / *Welcome message*. `{member_name}` is the native variable.

```
{member_name} 欢迎加入 mythos-agent 中文社区 🎉

30 秒上手三步:
1. 看置顶 —— 群规 + 快速链接
2. 官网: https://mythos-agent.com (首页 #demo 有 15 秒视频演示)
3. npx mythos-agent scan —— 无需 API key 立即跑扫描

有问题直接说,不用先问"可以提问吗"。
```

### 5.4 Launch-day announcement (post at 18:00 Beijing on 2026-04-22)

Post after the HN/Twitter thread goes live so Chinese users see the actual launch-moment links.

```markdown
mythos-agent v4.0.0 今天正式发布 🚀

感谢所有在这个群里提前预热的朋友,正是大家这几天的反馈让今天的发布更扎实。

🔗 发布页: https://mythos-agent.com
📦 安装: npx mythos-agent scan
🐙 Show HN: <在这里贴 HN 链接>
🐦 Twitter thread: <在这里贴 thread 链接>

如果这个工具对你有帮助,点 GitHub Star 是最直接的支持方式。
```

## 6. Permanent join link → `mythos-agent.com/feishu` redirect

1. Step 2 above gave you a group-join link like `https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=xxxxx`
2. Copy it
3. In `mythos-agent-landing/vercel.json`, find the `/feishu` redirect entry (added in this PR) and replace the placeholder `https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=PLACEHOLDER` with the real URL
4. Commit + push in the landing repo — Vercel auto-deploys in ~90 s
5. Verify: `curl -sI https://mythos-agent.com/feishu | head -3` returns 307 → the real Feishu invite URL

From this point forward, every mention of `mythos-agent.com/feishu` (Chinese README 社区 section, future marketing copy, Feishu's own group intro) will route to this invite. Rotating the invite later = update the destination in `vercel.json`; no docs need to change.

## 7. Verification checklist

Before firing the Show HN post, run through:

1. `https://mythos-agent.com/feishu` opens the Feishu invite page in an incognito browser → group name + description visible → "Join group" button works
2. Join test with a second Feishu account → you land in the group → welcome message sends
3. Pin the group announcement — confirm it shows at the top of the group list for new joiners
4. Post a test message in the group → admin can delete/mute problem messages
5. Members ≥ 10 before launch day — seed with Chinese dev contacts, Twitter CN handles, security-community friends. Cold groups feel dead and convert poorly.

## 8. Moderation budget (honest estimate)

| Phase | Time/day |
|---|---|
| Pre-launch (seed + onboarding) | 10 min |
| Launch day (0–24 h post-Show HN) | 1–2 h — answering in real time + cross-posting |
| Week 1 | 30–45 min |
| Steady-state (month 2+) | 10–15 min, if a CN co-admin emerges |

**Recruit a CN co-admin fast** — look for the first 1–2 users who answer other people's questions helpfully. Promote them to `管理员` role 3–5 days post-launch. Halves your ongoing load and retention improves sharply with a native-speaking voice in the group.

## 9. What to leave for after launch

- **WeChat group (if demand emerges)** — soft-demand signal comes from Feishu group members or GitHub Discussions asking for it. Threshold: 10+ requests → stand up per `docs/WECHAT-SETUP.md` (to be written then)
- **Feishu sub-topic groups** for contributors / rule discussion — after main group >200 members
- **GitHub webhook relay** for the `GitHub` bot — nice-to-have, not a launch blocker
- **Weekly CN office-hours** in the group — once there's a reliable audience attending
- **Cross-posts to 看雪论坛 (KanXue), 掘金 (Juejin), V2EX** — first wave on launch day, second wave with retro metrics at T+7 days

## 10. If Feishu doesn't work out

At ~1 month or whenever you have real traffic data, honestly re-evaluate:

- **Great signal**: members >100, average 10+ messages/day, 50%+ retention at 30 days → Feishu is working, keep investing
- **OK signal**: 50–100 members, slow but steady → keep Feishu, add WeChat as second channel for indie reach
- **Weak signal**: <50 members or near-dead → consolidate into Discord only, remove Feishu from README

This is the same threshold Discord will have for itself. Two parallel experiments; keep the one that works.
