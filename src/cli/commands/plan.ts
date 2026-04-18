import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import Anthropic from "@anthropic-ai/sdk";
import { loadConfig } from "../../config/config.js";
import { loadResults } from "../../store/results-store.js";
import type { Vulnerability } from "../../types/index.js";

interface PlanOptions {
  path?: string;
  json?: boolean;
}

const PLAN_PROMPT = `You are a security remediation planner. Given a list of vulnerabilities, create a prioritized remediation plan.

## Prioritization criteria:
1. **Severity** — critical and high first
2. **Exploitability** — findings with attack chains first
3. **Blast radius** — vulnerabilities affecting auth/data access first
4. **Fix complexity** — quick wins before complex refactors
5. **Dependencies** — fix foundational issues before dependent ones

## Output Format:
{
  "phases": [
    {
      "name": "Phase 1: Critical Fixes (immediate)",
      "timeframe": "1-2 days",
      "items": [
        {
          "findingId": "SPX-0001",
          "title": "SQL Injection in search endpoint",
          "action": "Replace string concatenation with parameterized query",
          "effort": "30 minutes",
          "file": "src/api/search.ts",
          "priority": 1
        }
      ]
    }
  ],
  "summary": "Brief executive summary of the remediation plan",
  "totalEstimate": "3-5 days"
}`;

export async function planCommand(options: PlanOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);
  const result = loadResults(projectPath);

  if (!result) {
    console.log(chalk.yellow("\n⚠️  No scan results. Run mythos-agent scan first.\n"));
    return;
  }

  if (result.confirmedVulnerabilities.length === 0) {
    console.log(chalk.green("\n✅ No vulnerabilities to remediate!\n"));
    return;
  }

  if (!config.apiKey) {
    // Generate a basic plan without AI
    renderBasicPlan(result.confirmedVulnerabilities);
    return;
  }

  const spinner = ora("Generating AI remediation plan...").start();

  try {
    const client = new Anthropic({ apiKey: config.apiKey });
    const vulnList = result.confirmedVulnerabilities
      .slice(0, 30)
      .map(
        (v) =>
          `- ${v.id} [${v.severity.toUpperCase()}] ${v.title}\n  File: ${v.location.file}:${v.location.line}\n  Category: ${v.category} | CWE: ${v.cwe || "N/A"}`
      )
      .join("\n\n");

    const chainInfo =
      result.chains.length > 0
        ? `\n\nAttack chains:\n${result.chains.map((c) => `- ${c.title} (${c.severity}): ${c.vulnerabilities.map((v) => v.id).join(" → ")}`).join("\n")}`
        : "";

    const response = await client.messages.create({
      model: config.model,
      max_tokens: 4096,
      system: PLAN_PROMPT,
      messages: [
        {
          role: "user",
          content: `Create a remediation plan for these ${result.confirmedVulnerabilities.length} vulnerabilities:\n\n${vulnList}${chainInfo}`,
        },
      ],
    });

    spinner.stop();

    const text = response.content.find((b) => b.type === "text");
    if (!text || text.type !== "text") {
      renderBasicPlan(result.confirmedVulnerabilities);
      return;
    }

    const jsonMatch = text.text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.log(text.text);
      return;
    }

    const plan = JSON.parse(jsonMatch[0]);

    if (options.json) {
      console.log(JSON.stringify(plan, null, 2));
      return;
    }

    // Render plan
    console.log(chalk.bold("\n📋 Remediation Plan\n"));
    console.log(chalk.dim("━".repeat(50)));

    if (plan.summary) {
      console.log(chalk.dim(`\n  ${plan.summary}\n`));
    }

    for (const phase of plan.phases || []) {
      console.log(chalk.bold(`\n  ${phase.name}`) + chalk.dim(` (${phase.timeframe})\n`));

      for (const item of phase.items || []) {
        const icon = item.priority === 1 ? "🔴" : item.priority === 2 ? "🟠" : "🟡";
        console.log(`    ${icon} ${chalk.bold(item.findingId || "")} ${item.title}`);
        console.log(chalk.dim(`       Action: ${item.action}`));
        console.log(chalk.dim(`       File: ${item.file || "N/A"} | Effort: ${item.effort}`));
      }
    }

    if (plan.totalEstimate) {
      console.log(chalk.bold(`\n  Total estimated effort: ${plan.totalEstimate}\n`));
    }

    console.log(
      chalk.dim("  Run ") +
        chalk.cyan("mythos-agent fix --apply") +
        chalk.dim(" to auto-generate patches.\n")
    );
  } catch (err) {
    spinner.fail(`Plan generation failed: ${err instanceof Error ? err.message : "error"}`);
    renderBasicPlan(result.confirmedVulnerabilities);
  }
}

function renderBasicPlan(vulns: Vulnerability[]) {
  console.log(chalk.bold("\n📋 Remediation Plan (basic — add API key for AI plan)\n"));

  const critical = vulns.filter((v) => v.severity === "critical");
  const high = vulns.filter((v) => v.severity === "high");
  const medium = vulns.filter((v) => v.severity === "medium");

  if (critical.length > 0) {
    console.log(chalk.red.bold(`  Phase 1: Fix ${critical.length} critical issues (immediate)\n`));
    for (const v of critical) {
      console.log(`    🔴 ${v.id} ${v.title} — ${v.location.file}:${v.location.line}`);
    }
  }

  if (high.length > 0) {
    console.log(chalk.yellow.bold(`\n  Phase 2: Fix ${high.length} high issues (this sprint)\n`));
    for (const v of high.slice(0, 10)) {
      console.log(`    🟠 ${v.id} ${v.title} — ${v.location.file}:${v.location.line}`);
    }
  }

  if (medium.length > 0) {
    console.log(chalk.blue.bold(`\n  Phase 3: Fix ${medium.length} medium issues (next sprint)\n`));
    for (const v of medium.slice(0, 10)) {
      console.log(`    🟡 ${v.id} ${v.title} — ${v.location.file}:${v.location.line}`);
    }
  }

  console.log();
}
