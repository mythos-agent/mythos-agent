# Contributing to mythos-agent

Thanks for your interest. mythos-agent — the **Mythos-Agent** — is an open-source AI security agent. We welcome code, rules, tests, docs, integrations, and ideas.

> **New here?** Jump to [Where to start](#where-to-start). The fastest first contribution is adding a test for an untested CLI command — every command in `src/cli/commands/` without a `__tests__` directory is fair game.
>
> **Looking for the strategic context?** [VISION.md](VISION.md) is the north star; [ROADMAP.md](ROADMAP.md) is the multi-year frame; the pinned issue **`[Roadmap] mythos-agent H1 2026 Goals`** is the active 6-month plan.

## Quick Start

```bash
git clone https://github.com/mythos-agent/mythos-agent.git
cd mythos-agent
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
npm run lint         # ESLint
npm run format       # Prettier
npm run typecheck    # TypeScript --noEmit
```

## Where to start

We label issues so you can find ones that match your background.

### Labels

| Label | Who it's for | Typical effort |
|---|---|---|
| `good-first-issue` — **scanner-rule** | First-time contributors familiar with one programming language | 1–3 hours |
| `good-first-issue` — **test** | First-time contributors comfortable with TypeScript / Vitest | 1–2 hours |
| `good-first-issue` — **docs** | Anyone | 30 min – 2 hours |
| `good-first-issue` — **integration** | Familiar with shell, subprocess, JSON | 2–6 hours |
| `help-wanted` — **analysis** | Dataflow / static analysis background | days–weeks |
| `help-wanted` — **agent** | LLM application or agent framework experience | days–weeks |
| 🙋 (in pinned Goals issue) | Specific in-flight item where a champion is wanted | varies |

### Concrete starter ideas

- **Scanner rule.** Pick a CWE not yet covered (audit list in [docs/benchmark.md](docs/benchmark.md) once it lands; until then, grep `src/scanner/` for the CWE you want to add). Add a regex / AST rule to the matching `*-scanner.ts`. Include a unit test in the matching `__tests__/` directory.
- **CLI test.** Pick any file under `src/cli/commands/*.ts` that does not have a sibling `__tests__/` test. Write a Vitest suite that exercises the command. The 80% CLI coverage bucket of the H1 2026 Goals tracks this campaign.
- **Tool integration.** Add a wrapper for an external scanner not yet integrated alongside Semgrep, Gitleaks, Trivy, Checkov, Nuclei. See [Adding tool integrations](#adding-tool-integrations).
- **Documentation example.** Pick a CLI command with terse `--help` and write a real-world example for `examples/`.

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
    taint-tracker.ts  AI-powered taint analysis (being replaced by analysis/taint-engine.ts)
    tools.ts          Basic agent tools (read, search, list)
    tools-advanced.ts Advanced tools (call graph, endpoints)
    providers/        Multi-model support (Anthropic, OpenAI, Ollama)

  cli/              44 CLI commands
  dast/             Dynamic analysis (fuzzer, PoC generator, payload library)
  scanner/          Static scanners (49 categories)
  tools/            External tool integrations (semgrep, gitleaks, trivy, checkov, nuclei)
  policy/           Policy-as-code engine (SOC2/HIPAA/PCI/GDPR/OWASP)
  report/           Output formatters (terminal, JSON, HTML, SARIF, dashboard)
  store/            Results persistence + scan cache
  server/           REST API
  mcp/              MCP server for Claude Code / Cursor / Copilot
  types/            TypeScript types
```

## Adding security rules

### Built-in rules
Edit `src/rules/builtin-rules.ts`. Each rule needs:
- `id`: unique identifier
- `title`: short description
- `description`: what the vulnerability is and how to fix it
- `severity`: critical, high, medium, low
- `category`: injection, xss, secrets, etc.
- `cwe`: CWE ID (no `CWE-XXX` placeholders — use the actual CWE)
- `languages`: which languages this applies to
- `patterns`: regex patterns to match

Add a unit test that asserts both a true-positive (vulnerable code → match) and a true-negative (safe code → no match). Tests for false-positive avoidance are particularly welcome.

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
Publishable as separate npm packages:
```bash
mythos-agent rules init my-pack
cd mythos-agent-rules-my-pack
# edit rules.yml
npm publish
```

The `mythos-agent-rules-*` npm prefix is reserved for community rule packs. The forthcoming **scanner plugin SDK** (Q3 2026 milestone in ROADMAP) will document a programmatic alternative to YAML rules for cases that need real logic.

## Adding tool integrations

1. Create `src/tools/my-tool.ts` following the pattern in existing wrappers (semgrep, gitleaks, trivy, checkov, nuclei)
2. Export a `runMyTool(projectPath)` function that returns `Vulnerability[]`
3. Add the tool to `src/tools/index.ts` in `runAllTools()`
4. Add install check to `src/tools/tool-runner.ts` in `TOOL_COMMANDS`
5. Add a unit test in `src/tools/__tests__/`

## Writing tests

Tests use [Vitest](https://vitest.dev/) and live in `__tests__/` directories alongside the code under test.

```bash
npm test                    # run all
npx vitest run src/analysis # run a specific directory
npx vitest --watch          # watch mode
npm run test:coverage       # with coverage report
```

### Testing policy

To satisfy [OpenSSF Best Practices Passing tier](docs/security/openssf-badge-application.md) criterion 25 and to keep regression risk manageable, every PR is expected to:

1. **Add tests for new behavior.** New scanners, CLI commands, analysis modules, agent tools, and rule packs require both happy-path and error-path tests. New rules require both true-positive and true-negative tests; false-positive avoidance tests are welcomed and will be merged faster.
2. **Update tests for changed behavior.** If the change alters output (CLI text, JSON shape, report format), update the affected tests in the same PR.
3. **Not regress coverage.** PRs that drop measured branch coverage by more than 1 percentage point require maintainer override with rationale in the PR description.

PRs that touch only docs, comments, or formatting are exempt. PRs that fix a security regression must include a regression test for the specific vulnerability class.

The `demo-vulnerable-app/` directory is a deliberate test fixture — use it freely for scanner tests.

## RFC process (for substantial changes)

Substantial changes — anything that will affect more than one area, change a public CLI / API surface, or alter governance — go through a lightweight RFC.

- **Template:** [`docs/RFC-TEMPLATE.md`](docs/RFC-TEMPLATE.md)
- **Process:** [`docs/rfcs/README.md`](docs/rfcs/README.md)
- **Discussion window:** 14 days minimum for substantive changes; 3–7 days for non-trivial but bounded ones (lazy consensus per [GOVERNANCE.md](GOVERNANCE.md))

Required for: new scanner phases, breaking CLI changes, governance changes, new AI provider integrations, scanner plugin SDK changes, license-related decisions.
Optional for: scanner rules, integrations, bug fixes.

## Pull request guidelines

1. Run `npm run build && npm test && npm run lint && npm run typecheck` before submitting
2. Add or update tests per the [testing policy](#testing-policy) above
3. Keep commits focused — one feature / fix per commit
4. Use [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, `style:`, `ci:`, `perf:`. The `release-please` workflow uses these to drive semver and the CHANGELOG.
5. Update README, VISION, or ROADMAP if your change shifts user-facing capability or strategic direction
6. Sign your commits (`git commit -s`) — Developer Certificate of Origin sign-off. We do not require a CLA; sign-off is enough.

## Recognition

Contributors are listed in:

- The auto-updated [Mythos-Agent Pioneers leaderboard](docs/pioneers.md) (lands H1 2026)
- Release notes for the release containing your change
- The all-contributors section of the README (when set up)

A scanner-rule and scanner-module **bounty program** is drafted but currently **inactive**; it activates upon first corporate user OR $5K/month recurring sponsorship. See [`docs/bounty.md`](docs/bounty.md) (lands H1 2026 Session 5) and the [community on-ramp section of the roadmap](ROADMAP.md#5-contributor-on-ramp).

## Responsible use

mythos-agent is a defensive tool. By contributing, you agree to use it — and to design contributions that — primarily serve defenders.

- **Do not** use mythos-agent to scan systems you do not own or have explicit written permission to test.
- **Do not** contribute scanners or AI prompts whose primary purpose is to enable offensive operations against systems the user does not control.
- **Do** contribute scanners that detect attacker techniques so defenders can find and remove them.
- **Responsibly disclose** any zero-day vulnerability that mythos-agent helps you find — do not weaponize it.
- The mythos-agent maintainers reserve the right to decline contributions that materially shift the project's defensive posture.

This is not a moral statement; it is the project's position. People who build offensive tooling are welcome to fork (MIT permits it). They must do so under a different brand.

## Code of Conduct

All project spaces follow the [Code of Conduct](./CODE_OF_CONDUCT.md). Be kind, be constructive, be collaborative. Reports of violations: conduct@sphinx-agent.dev.

## License

By contributing, you agree your contribution is licensed under [MIT](./LICENSE), the same license as the project (inbound = outbound). No CLA required; the DCO sign-off in your commits is enough.

The maintainers commit publicly that scanner code contributed under MIT will remain MIT in perpetuity (see [GOVERNANCE.md § License Firewall](GOVERNANCE.md#license-firewall)).
