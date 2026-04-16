# Contributing to sphinx-agent

Thanks for your interest in contributing! sphinx-agent is an open-source AI security agent, and we welcome contributions of all kinds.

## Quick Start

```bash
git clone https://github.com/sphinx-agent/sphinx-agent.git
cd sphinx-agent
npm install
npm run build
npm test
```

## Development

```bash
npm run dev          # Watch mode (recompile on change)
npm run build        # Build TypeScript
npm test             # Run tests
npm run test:watch   # Watch mode tests
```

## Project Structure

```
src/
  agents/           Multi-agent orchestrator
    orchestrator.ts   Pipeline: Recon → Hypothesis → Analyze → Exploit
    recon-agent.ts    Maps attack surface
    hypothesis-agent.ts  Generates security hypotheses (Mythos technique)
    analyzer-agent.ts    Combines all scanners + AI
    exploit-agent.ts     Chains vulns + PoCs
    agent-protocol.ts    Typed messages between agents

  analysis/         Code analysis engine
    code-parser.ts    Multi-language AST parsing (JS/TS/Python/Go)
    call-graph.ts     Inter-procedural call graph
    endpoint-mapper.ts  API route discovery + auth assessment
    taint-engine.ts   Deterministic source-to-sink tracking
    variant-analyzer.ts  CVE variant detection (Big Sleep technique)
    service-mapper.ts  Docker/K8s service mapping

  agent/            AI integration
    analyzer.ts       Claude API agentic analysis
    fixer.ts          AI patch generation
    fix-validator.ts  Patch validation pipeline
    query-engine.ts   Natural language queries
    taint-tracker.ts  AI-powered taint analysis
    tools.ts          Basic agent tools (read, search, list)
    tools-advanced.ts Advanced tools (call graph, endpoints)
    providers/        Multi-model support (Anthropic, OpenAI, Ollama)

  cli/              58 CLI commands
  dast/             Dynamic analysis
    fuzzer.ts         Basic payload fuzzer
    smart-fuzzer.ts   AI-guided fuzzer with feedback loop
    poc-generator.ts  Proof-of-concept exploit generator
    payload-generator.ts  Security test payloads

  scanner/          Static scanners
    pattern-scanner.ts  Regex-based rule engine
    secrets-scanner.ts  Secret detection (22 patterns + entropy)
    dep-scanner.ts      Dependency scanning (OSV API)
    iac-scanner.ts      IaC scanning (Docker/Terraform/K8s)
    lockfile-parsers.ts 10 lockfile format parsers
    diff-scanner.ts     Git diff scanning

  tools/            External tool integrations
    semgrep.ts, gitleaks.ts, trivy.ts, checkov.ts, nuclei.ts

  policy/           Policy-as-code engine
  report/           Output formatters (terminal, JSON, HTML, SARIF, dashboard)
  store/            Results persistence + scan cache
  types/            TypeScript types
```

## Adding Security Rules

### Built-in rules
Edit `src/rules/builtin-rules.ts`. Each rule needs:
- `id`: unique identifier
- `title`: short description
- `description`: what the vulnerability is and how to fix it
- `severity`: critical, high, medium, low
- `category`: injection, xss, secrets, etc.
- `cwe`: CWE ID
- `languages`: which languages this applies to
- `patterns`: regex patterns to match

### Custom YAML rules
Create `.sphinx/rules/*.yml`:
```yaml
rules:
  - id: my-rule
    title: My Custom Rule
    description: What it detects and how to fix
    severity: high
    category: custom
    languages: ["*"]
    patterns:
      - pattern: "dangerous_function\\("
```

### Rule packs
Create a publishable rule pack:
```bash
sphinx-agent rules init my-pack
cd sphinx-rules-my-pack
# edit rules.yml
npm publish
```

## Adding Tool Integrations

1. Create `src/tools/my-tool.ts` following the pattern in existing wrappers
2. Export a `runMyTool(projectPath)` function that returns `Vulnerability[]`
3. Add the tool to `src/tools/index.ts` in `runAllTools()`
4. Add install check to `src/tools/tool-runner.ts` in `TOOL_COMMANDS`

## Writing Tests

Tests use [vitest](https://vitest.dev/) and live in `__tests__/` directories:

```bash
npm test                    # run all
npx vitest run src/analysis # run specific directory
npx vitest --watch          # watch mode
```

Use the `demo-vulnerable-app/` as a test fixture for scanner tests.

## Pull Request Guidelines

1. Run `npm run build && npm test` before submitting
2. Add tests for new features
3. Keep commits focused — one feature/fix per commit
4. Update README if adding user-facing features

## Code of Conduct

Be kind, be constructive, be collaborative. We're all here to make security accessible to everyone.
