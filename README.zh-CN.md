<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong>
</p>

<p align="center">
  <img alt="mythos-agent — Cerby the guard puppy" src="assets/cerby-banner.svg" width="640">
</p>

<p align="center">
  <img alt="mythos-agent — 10-second security check demo" src="assets/demo.gif" width="720">
</p>

<p align="center">
  <h1 align="center">mythos-agent</h1>
  <p align="center"><strong>面向应用安全的 AI 代码审阅助手</strong></p>
  <p align="center"><em>开源。读你的代码、标记可能的安全问题、解释推理过程、给出修复建议。</em></p>
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
  <a href="#quick-start">快速开始</a> &bull;
  <a href="#how-it-works">工作原理</a> &bull;
  <a href="#commands">命令清单</a> &bull;
  <a href="#hunt-mode">狩猎模式</a> &bull;
  <a href="#variant-analysis">变体分析</a> &bull;
  <a href="#integrations">集成</a> &bull;
  <a href="#contributing">贡献指南</a> &bull;
  <a href="VISION.md">愿景</a> &bull;
  <a href="ROADMAP.md">路线图</a>
</p>

---

mythos-agent **用一位专职安全审阅者的方式来审阅你的代码** —— 系统性地走过常见的问题模式、查找已知 CVE 的结构变体、按置信度排序发现、并给出可以直接采纳或拒绝的修复建议。灵感与 Anthropic 内部的 Mythos 安全代理同源，但本项目是独立实现、并非克隆、也无任何隶属关系。完整定位见 [VISION.md](VISION.md)。

> **给新贡献者**：为期 6 个月的当前工作计划见置顶 Issue **`[Roadmap] mythos-agent H1 2026 Goals`**。带 🙋 标记的条目是欢迎协作的部分。刚加入？参考 [CONTRIBUTING.md](CONTRIBUTING.md) 里的 `good-first-issue` 指引。
>
> **给安全团队与 EU CRA 合规的下游制造商**：漏洞披露 SLA 见 [SECURITY.md](SECURITY.md)，EU CRA 角色声明见 [docs/security/cra-stance.md](docs/security/cra-stance.md)，公开威胁模型见 [docs/security/threat-model.md](docs/security/threat-model.md)，版本策略与 LTS/EOL 政策见 [RELEASES.md](RELEASES.md)。OpenSSF Best Practices Badge（Passing 层）申请目标为 **2026 年 6 月**；发布产物通过 [Sigstore](docs/security/sbom.md) 签名，并附带 [CycloneDX SBOM](docs/security/sbom.md) 供下游 Manufacturer 合规使用。

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

<a name="quick-start"></a>
## 快速开始

```bash
# 安装
npm install -g mythos-agent

# 快速扫描（无需 API key）
mythos-agent scan

# 完整自主狩猎（需要 API key）
mythos-agent init
mythos-agent hunt

# 查找已知 CVE 的变体
mythos-agent variants CVE-2021-44228

# 自然语言提问
mythos-agent ask "are there any auth bypasses?"

# 查看当前已安装的外部工具
mythos-agent tools
```

<a name="how-it-works"></a>
## 工作原理

mythos-agent 把 **其他开源工具从未同时做到的三件事** 组合到一起：

### 1. 假设驱动的扫描（Hypothesis-Driven Scanning）
不再只匹配已知模式，而是让 AI **推理"可能出错的地方"** —— 比如生成"这个事务没有对行加锁，存在竞态条件风险"、"这段认证校验使用了字符串相等比较，存在时序攻击风险"这类假设。

### 2. 变体分析（Variant Analysis，Big Sleep 技术）
给定一个已知 CVE，mythos-agent 能在你的代码库里找出 **结构相似但语法不同** 的代码 —— 同一个根因、不同的出现位置。这正是 Google 的 Big Sleep 用来发现 20 个真实 0day 的方法。

### 3. 多阶段验证（Multi-Stage Verification）
每一条发现都要走一条置信度流水线：
- **Pattern scan** → 候选项
- **AI 假设** → 理论风险确认
- **智能 fuzzer** → 动态测试
- **PoC 生成器** → 用具体利用脚本证明确实存在

只有穿过多个阶段的发现才会被标记为 "confirmed"。

<a name="commands"></a>
## 命令清单

| 命令 | 说明 |
|---------|-------------|
| `hunt [path]` | 完整自主多代理扫描（Recon → Hypothesize → Analyze → Exploit） |
| `scan [path]` | 标准扫描（patterns + secrets + deps + IaC + AI） |
| `variants [cve-id]` | 在代码库中查找指定 CVE 的变体 |
| `fix [path]` | AI 生成补丁，可加 `--apply` 直接应用 |
| `ask [question]` | 自然语言安全问询 |
| `taint [path]` | AI 驱动的数据流 / 污点分析 |
| `watch` | 持续监控 —— 文件保存时自动扫描 |
| `dashboard` | 本地 Web UI，展示图表与发现表 |
| `report [path]` | 输出为 terminal / JSON / HTML / SARIF |
| `policy` | 以代码描述策略，支持 SOC2 / HIPAA / PCI / OWASP 合规映射 |
| `rules` | 社区规则包注册表（搜索/安装/发布） |
| `tools` | 检查本机已安装的外部安全工具 |
| `init` | 配置向导（Anthropic / OpenAI / Ollama / LM Studio） |

<a name="hunt-mode"></a>
## 狩猎模式（Hunt Mode）

`mythos-agent hunt` 会运行完整的多代理流水线：

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

<a name="variant-analysis"></a>
## 变体分析

在你的项目里找出与已知 CVE 同根因的代码：

```bash
# 搜索类似 Log4Shell 的模式
mythos-agent variants CVE-2021-44228

# 自动检测并扫描变体
mythos-agent variants --auto
```

变体分析器从 CVE 中提取 **根因模式**（而不是表面语法），再在代码库里搜索结构相似的代码。

<a name="scanners"></a>
## 扫描器（15 个已接入 + 28 个实验中，共 329+ 条规则）

**Default** 扫描器会在每次 `mythos-agent scan` 时运行。**Experimental** 扫描器是已经实现并通过单元测试、已随 tarball 一起发布、但还没有从 CLI / HTTP / MCP / agent 入口接通的类 —— 由 wiring-invariant 测试里的 [`KNOWN_EXPERIMENTAL`](src/scanner/__tests__/wiring-invariant.test.ts) 追踪。

| 分类 | 检测内容 | 规则数 | 状态 |
|----------|---------------|-------|--------|
| Code patterns | SQLi、XSS、命令注入、eval、SSRF 等 | 25+ | Default |
| Framework rules | React、Next.js、Express、Django、Flask、Spring、Go | 27 | Default |
| Secrets | AWS、GitHub、Stripe、API key、数据库 URL、私钥 + 熵值判断 | 22 | Default |
| Dependencies (SCA) | 通过 OSV API 识别已知 CVE（支持 10 种 lockfile 格式） | OSV | Default |
| IaC | Docker、Terraform、Kubernetes 错配 | 13 | Default |
| AI/LLM Security | 提示词注入、对 AI 输出的不安全 eval、cost 攻击 | 13 | Default |
| API Security | OWASP API Top 10：BOLA、mass assignment、broken auth | 12 | Default |
| Cloud Misconfig | AWS/Azure/GCP：公开的存储、通配符 IAM、开放防火墙 | 14 | Default |
| Security Headers | CSP、HSTS、X-Frame-Options、Referrer-Policy | 8 | Default |
| JWT | 算法、过期、存储、撤销、audience | 9 | Default |
| Session | 固定、过期、cookie 标志、localStorage token | 7 | Default |
| Business Logic | 负数金额、优惠券复用、库存竞态、角色越权 | 6 | Default |
| Crypto Audit | 弱哈希、ECB 模式、硬编码密钥、弃用的 TLS | 11 | Default |
| Privacy/GDPR | PII 处理、同意、数据留存（映射到 GDPR 条款） | 9 | Default |
| Race Conditions | TOCTOU、非原子操作、double-spend、缺失事务 | 7 | Default |
| ReDoS | 正则回溯爆炸（嵌套量词、重叠备选） | — | Default |
| Supply Chain | 错拼攻击、依赖混淆、危险的 install 脚本 | 12 | Experimental |
| Zero Trust | 服务间信任、mTLS、网络分段、基于 IP 的鉴权 | 8 | Experimental |
| GraphQL | introspection、深度限制、字段鉴权、批处理 | 8 | Experimental |
| WebSocket | 鉴权、origin 校验、消息校验、广播 XSS | 7 | Experimental |
| CORS | origin 反射、credentials 处理、子串绕过 | 7 | Experimental |
| OAuth/OIDC | 缺少 state、无 PKCE、implicit flow、client secret 外泄 | 7 | Experimental |
| SSTI | Jinja2、EJS、Handlebars、Pug、Nunjucks、Twig、Go 模板 | 7 | Experimental |

<details>
<summary>其余 21 个 experimental 扫描器（暂未接入默认扫描）</summary>

SQL injection deep、XSS deep、NoSQL、命令注入、反序列化、路径遍历、open redirect、XXE、输入校验、clickjacking、DNS rebinding、子域枚举、依赖混淆、环境变量、日志、错误处理、缓存、邮件、上传、内存安全、权限。

每一个都以类的形式存在于 `src/scanner/` 下，并在 `src/scanner/__tests__/coverage-scanners.test.ts` / `new-scanners.test.ts` 有单元测试，但还没有被任何 CLI 命令、HTTP API 路由、MCP handler 或 agent pipeline 调用。延期原因参见 wiring-invariant 测试中的 `KNOWN_EXPERIMENTAL`。接通流程可以参照 `main` 上的 HeadersScanner / JwtScanner / SessionScanner / BusinessLogicScanner 接通提交。

</details>

除上述扫描器外，mythos-agent 还提供互补分析（不计入扫描器总数）：call-graph + 污点引擎、DAST 智能 fuzzer、AI 假设代理、变体分析、Git 历史挖掘。

**外部工具集成**：Semgrep（30+ 语言）、Gitleaks（100+ 模式）、Trivy（SCA + 容器）、Checkov（1000+ IaC 策略）、Nuclei（9000+ DAST 模板）。

<a name="integrations"></a>
## 集成

| 平台 | 内容 |
|----------|------|
| **VS Code** | 插件，提供行内诊断 + 一键 AI 修复 |
| **GitHub Action** | push/PR 时扫描 + SARIF 上传到 Code Scanning |
| **PR Review Bot** | 在 PR 的脆弱代码行上内联评论 |
| **Dashboard** | 本地 Web UI，通过 `mythos-agent dashboard` 启动 |
| **SARIF** | 对接 GitHub Code Scanning、VS Code、任何 SARIF 工具 |
| **Policy Engine** | 策略即代码，含 SOC2 / HIPAA / PCI-DSS / OWASP 合规映射 |

<a name="ai-providers"></a>
## AI 模型服务商

| 提供方 | 模型 | 费用 |
|----------|--------|------|
| **Anthropic** | Claude Sonnet 4、Claude Opus 4.6 | 按 API 计费 |
| **OpenAI** | GPT-4o、GPT-4o-mini、o1 | 按 API 计费 |
| **Ollama** | Llama、CodeLlama、DeepSeek、Qwen | 免费（本地） |
| **LM Studio** | 任意 GGUF 模型 | 免费（本地） |

Pattern 扫描、secrets、deps、IaC 完全不需要 API key。

<a name="comparison"></a>
## 对比

| 能力 | mythos-agent | Semgrep | Snyk | CodeQL | Nuclei |
|---------|-------------|---------|------|--------|--------|
| Pattern 扫描 | 有 | 最强 | 有 | 有 | 模板 |
| **假设驱动扫描** | **有** | 无 | 无 | 无 | 无 |
| **变体分析** | **有** | 无 | 无 | 部分 | 无 |
| **AI 引导 fuzzing** | **有** | 无 | 无 | 无 | 模板 |
| **PoC 生成** | **有** | 无 | 无 | 无 | 无 |
| AI 深度分析 | 有 | 无 | 有限 | 无 | 无 |
| 漏洞链接串联 | 有 | 无 | 无 | 无 | 无 |
| AI 自动修复 | 有 | 无 | Fix PR | 无 | 无 |
| 自然语言查询 | 有 | 无 | 无 | 无 | 无 |
| Secrets | 有 | 有 | 有 | 无 | 无 |
| SCA | 有 | 无 | 最强 | 无 | 无 |
| IaC | 有 | 无 | 有 | 无 | 模板 |
| DAST | 有 | 无 | 无 | 无 | 最强 |
| 开源 | 是 | 部分 | 否 | 是 | 是 |

<a name="contributing"></a>
## 贡献指南

详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

```bash
git clone https://github.com/mythos-agent/mythos-agent.git
cd mythos-agent && npm install && npm run build && npm test
```

<a name="architecture"></a>
### 架构

```
src/
  agents/         多代理编排器 + Recon / Hypothesis / Analyzer / Exploit 代理
  analysis/       代码解析器、调用图、污点引擎、变体分析器、服务映射
  agent/          AI 集成、提示词、工具、修复校验
  cli/            15 个 CLI 命令
  dast/           智能 fuzzer、PoC 生成器、payload 库
  policy/         策略引擎 + 合规映射
  report/         Terminal、JSON、HTML、SARIF、dashboard
  rules/          内置规则 + 自定义 YAML + 社区注册表
  scanner/        Pattern、secrets、deps、IaC、diff 扫描器
  store/          结果持久化 + 增量缓存
  tools/          外部工具封装（Semgrep、Trivy 等）
vscode-extension/ VS Code 插件
action/           GitHub Actions
bot/              PR Review Bot
```

<a name="community"></a>
## 社区

- **Discord**：[mythos-agent.com/discord](https://mythos-agent.com/discord) —— 主要交流渠道。`#help` 提问，`#rule-ideas` 提新扫描器规则，`#general` 闲聊。
- **GitHub Discussions**：[Q&A](https://github.com/mythos-agent/mythos-agent/discussions/categories/q-a) / [Ideas](https://github.com/mythos-agent/mythos-agent/discussions/categories/ideas)
- **安全漏洞上报**：`security@mythos-agent.com`（见 [SECURITY.md](SECURITY.md)，48 小时内确认）
- **行为准则反馈**：`conduct@mythos-agent.com`
- **微信群**：即将开放 —— 想第一时间拿到邀请，在 Discord `#general` 留言或在 GitHub Discussions 里回复 "WeChat please"，达到 10+ 意向后会开群。

<a name="license"></a>
## 许可证

MIT
