# Open Mythos Blueprint

## The Vision

Build an open-source autonomous security agent by **orchestrating the best existing tools** with AI reasoning. Don't reinvent scanners — unify them under an intelligent agent that thinks like a security researcher.

```
┌─────────────────────────────────────────────────────────┐
│                    sphinx-agent                          │
│              AI Orchestration Layer                      │
│         (Claude / OpenAI / Local Models)                 │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  Recon   │→ │ Analyze  │→ │ Exploit  │→ Report     │
│  │  Agent   │  │  Agent   │  │  Agent   │             │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘             │
│       │              │              │                    │
├───────┼──────────────┼──────────────┼────────────────────┤
│       ▼              ▼              ▼                    │
│  ┌─────────────────────────────────────────────────┐    │
│  │           Open-Source Tool Layer                  │    │
│  │                                                  │    │
│  │  SAST: Semgrep, Bandit, gosec                   │    │
│  │  Secrets: Gitleaks                               │    │
│  │  SCA: Trivy, Grype, OSV API                     │    │
│  │  IaC: Checkov                                    │    │
│  │  DAST: Nuclei, ZAP                              │    │
│  │  Code: tree-sitter (AST), CodeQL                │    │
│  │  Containers: Trivy, Syft                         │    │
│  │  Network: nmap, httpx, subfinder                 │    │
│  │  Exploit: sqlmap, custom PoC gen                 │    │
│  │  Vuln DBs: OSV, NVD, EPSS                       │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## What We're Combining

### Tier 1: Must-Have Integrations (build first)

| Tool | What it gives us | Stars | License | Integration |
|------|-----------------|-------|---------|-------------|
| **Semgrep** | Best-in-class SAST, 30+ languages, custom YAML rules | 11k | LGPL-2.1 | `semgrep --json` |
| **Gitleaks** | Fast secrets scanning, 100+ patterns | 18k | MIT | `gitleaks detect --report-format json` |
| **Trivy** | SCA + containers + IaC in one binary | 24k | Apache-2.0 | `trivy fs --format json` |
| **Nuclei** | DAST with 9000+ community templates | 21k | MIT | `nuclei -jsonl` |
| **tree-sitter** | AST parsing for 100+ languages | 19k | MIT | Node/Python bindings |

### Tier 2: Power Integrations (build second)

| Tool | What it gives us | Stars | License | Integration |
|------|-----------------|-------|---------|-------------|
| **Checkov** | 1000+ IaC policies (Terraform/K8s/Docker/CloudFormation) | 7k | Apache-2.0 | `checkov -o json` |
| **Syft** | SBOM generation for containers | 6k | Apache-2.0 | `syft -o json` |
| **httpx** | Fast HTTP probing for DAST | 8k | MIT | `httpx -json` |
| **EPSS API** | Exploit probability scoring for prioritization | Free API | — | REST API |
| **ZAP** | Deep web app DAST with REST API | 13k | Apache-2.0 | REST API |

### Tier 3: Advanced Integrations (build later)

| Tool | What it gives us | Integration |
|------|-----------------|-------------|
| **nmap** | Network reconnaissance | `nmap -oX` (XML output) |
| **sqlmap** | SQL injection exploitation + PoC | `sqlmap --batch --forms` |
| **Ghidra** | Binary analysis (headless mode) | `analyzeHeadless` script |
| **Wazuh** | SIEM/XDR integration | REST API |
| **Falco** | Runtime container threat detection | gRPC output |

## Architecture: Multi-Agent Swarm

Inspired by Pentest Swarm AI and AWS multi-agent pentest architecture:

```
                    ┌──────────────┐
                    │ Orchestrator │
                    │   Agent      │
                    └──────┬───────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
     ┌────────────┐ ┌────────────┐ ┌────────────┐
     │   Recon    │ │  Analyzer  │ │  Exploit   │
     │   Agent    │ │   Agent    │ │   Agent    │
     └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
           │               │               │
           ▼               ▼               ▼
     ┌──────────┐   ┌──────────┐   ┌──────────┐
     │ Tools:   │   │ Tools:   │   │ Tools:   │
     │ nmap     │   │ Semgrep  │   │ Nuclei   │
     │ httpx    │   │ Trivy    │   │ sqlmap   │
     │ subfinder│   │ Gitleaks │   │ ZAP      │
     │ tree-sitter  │ Checkov  │   │ PoC gen  │
     └──────────┘   │ tree-sitter  └──────────┘
                    │ EPSS     │
                    └──────────┘
```

### Agent Roles

**Orchestrator Agent** — the brain
- Decomposes scan target into tasks
- Dispatches to specialized agents
- Synthesizes findings into attack chains
- Generates final report with prioritization

**Recon Agent** — map the attack surface
- Discover endpoints (API routes, web pages, network services)
- Map codebase architecture (entry points, auth boundaries, data stores)
- Build dependency graph
- Identify technology stack

**Analyzer Agent** — find vulnerabilities
- Run Semgrep/Gitleaks/Trivy/Checkov against codebase
- Use tree-sitter AST for deep code understanding
- AI reasoning to verify findings, dismiss false positives
- Discover business logic and auth flaws that tools miss
- Cross-file taint tracking
- Score findings with CVSS + EPSS

**Exploit Agent** — prove exploitability
- Generate proof-of-concept payloads for confirmed vulnerabilities
- Run Nuclei templates against live targets
- Chain vulnerabilities into multi-step attack paths
- Validate exploits in sandboxed environment

**Reporter Agent** — communicate findings
- Generate prioritized reports (terminal, HTML, SARIF, PDF)
- Map findings to compliance frameworks (SOC2, HIPAA, PCI, OWASP)
- Produce executive summary + technical details
- Create remediation plan with AI-generated patches

## What We Replicate from Commercial Products

| Company/Product | Their Capability | Our Open-Source Approach |
|----------------|-----------------|------------------------|
| **Snyk** | Developer-first SCA + auto-fix PRs | Trivy/Grype + AI-generated fix + `sphinx-agent fix --apply` |
| **Wiz** | Graph-based cloud risk correlation | Multi-tool findings → AI-built vulnerability graph |
| **Checkmarx** | Cross-file taint analysis | tree-sitter AST + AI data flow tracing |
| **Veracode** | Binary analysis (no source) | Ghidra headless + AI reasoning on decompiled code |
| **Pentera/Horizon3** | Autonomous breach simulation | Nuclei + sqlmap + AI-driven exploit chaining |
| **CrowdStrike Charlotte AI** | Natural language threat hunting | `sphinx-agent ask` with tool-augmented AI |
| **Darktrace** | Network anomaly detection | Zeek/Suricata logs + AI behavioral analysis |
| **Socket.dev** | Package behavior analysis | Sandbox execution + AI behavioral review |
| **SonarQube** | Continuous code quality + security | `sphinx-agent watch` + Semgrep rules |

## Implementation Plan

### Phase 1: Tool Integration Layer (2-3 weeks)
**Goal:** Replace our custom regex scanner with real tools.

```
src/tools/
  ├── tool-runner.ts      — unified subprocess runner with JSON parsing
  ├── semgrep.ts          — Semgrep integration (SAST)
  ├── gitleaks.ts         — Gitleaks integration (secrets)
  ├── trivy.ts            — Trivy integration (SCA + containers + IaC)
  ├── checkov.ts          — Checkov integration (IaC policies)
  ├── nuclei.ts           — Nuclei integration (DAST)
  ├── tree-sitter.ts      — AST parsing for code understanding
  └── osv.ts              — OSV + EPSS API integration
```

Each tool wrapper:
- Checks if tool is installed (graceful fallback to built-in rules)
- Runs via subprocess with JSON output
- Normalizes findings to our `Vulnerability` type
- Handles timeouts and errors

Add CLI: `sphinx-agent tools check` — verify which tools are installed
Add CLI: `sphinx-agent tools install` — auto-install missing tools

### Phase 2: Multi-Agent Architecture (3-4 weeks)
**Goal:** Upgrade from single-pass scan to multi-agent orchestration.

```
src/agents/
  ├── orchestrator.ts     — task decomposition + agent dispatch
  ├── recon-agent.ts      — attack surface mapping
  ├── analyzer-agent.ts   — vulnerability discovery (upgrades current analyzer)
  ├── exploit-agent.ts    — exploitation + PoC generation
  ├── reporter-agent.ts   — report generation + remediation planning
  └── agent-protocol.ts   — typed message passing between agents
```

Key design decisions:
- Use Claude Agent SDK for agent orchestration
- Each agent has scoped tool access (recon can't exploit)
- Structured JSON messages between agents (not free-text)
- Agent state persisted to `.sphinx/` for resumability

### Phase 3: Advanced Analysis Engine (3-4 weeks)
**Goal:** Deep code understanding that goes beyond what any individual tool provides.

```
src/analysis/
  ├── ast-analyzer.ts     — tree-sitter based multi-language AST analysis
  ├── call-graph.ts       — inter-procedural call graph construction
  ├── taint-engine.ts     — deterministic taint propagation + AI verification
  ├── auth-mapper.ts      — map all auth/authz enforcement points
  ├── endpoint-mapper.ts  — discover all API/web endpoints from code
  └── vuln-graph.ts       — graph DB of findings with exploitation edges
```

### Phase 4: Dynamic Analysis (3-4 weeks)
**Goal:** Confirm vulnerabilities by actually testing them.

```
src/dast/
  ├── target-launcher.ts  — start the application under test
  ├── endpoint-fuzzer.ts  — AI-guided fuzzing of discovered endpoints
  ├── exploit-runner.ts   — execute Nuclei/sqlmap/custom PoCs
  ├── sandbox.ts          — Docker-based isolation for exploit execution
  └── finding-correlator.ts — correlate SAST + DAST findings
```

New command: `sphinx-agent pentest [target]` — full autonomous penetration test

### Phase 5: Enterprise Features (4-6 weeks)
**Goal:** What makes enterprises pay $100K-$1M/yr for Snyk/Wiz/Checkmarx.

- Container image scanning with SBOM (Trivy + Syft)
- Cloud misconfiguration scanning (Prowler/ScoutSuite integration)
- CI/CD pipeline integration (GitLab CI, Jenkins, Azure DevOps)
- Vulnerability management dashboard with trend tracking
- Team management and RBAC
- Custom compliance framework definitions
- API for programmatic access
- Slack/Teams/PagerDuty notifications

## What Makes This Better Than Anything Else

1. **Unified** — one tool instead of 10. Semgrep for SAST, Trivy for SCA, Gitleaks for secrets, Nuclei for DAST, Checkov for IaC — all orchestrated by one agent.

2. **AI-native** — not "tool + AI bolt-on" like CrowdStrike/SentinelOne. The AI IS the orchestrator. It reasons about findings, chains them, and generates fixes.

3. **Open-source** — enterprises pay $100K-$1M/yr for Snyk+Wiz+Checkmarx. We give them 80% of that value for free.

4. **Autonomous** — doesn't just scan and report. Investigates like a researcher, proves exploitability, generates validated fixes.

5. **Developer-first** — CLI, VS Code extension, GitHub Action, PR bot. Security in the developer workflow, not a separate portal.

## Name: sphinx-agent
**Tagline:** "The AI security agent that guards your code. Open-source Mythos for everyone."
