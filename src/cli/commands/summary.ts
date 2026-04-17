import path from "node:path";
import chalk from "chalk";
import { loadConfig } from "../../config/config.js";
import { loadResults } from "../../store/results-store.js";
import { loadHistory } from "../../store/history.js";
import { loadBaseline, compareToBaseline } from "../../store/baseline.js";
import { loadSuppressions } from "../../store/suppressions.js";
import { checkAllTools } from "../../tools/index.js";
import { loadPolicy, evaluatePolicy } from "../../policy/engine.js";
import { findConfigFile } from "../../config/config.js";
import type { Vulnerability } from "../../types/index.js";

interface SummaryOptions {
  path?: string;
}

export async function summaryCommand(options: SummaryOptions) {
  const projectPath = path.resolve(options.path || ".");
  const projectName = path.basename(projectPath);
  const config = loadConfig(projectPath);
  const result = loadResults(projectPath);
  const history = loadHistory(projectPath);
  const suppressions = loadSuppressions(projectPath);
  const tools = checkAllTools();
  const configFile = findConfigFile(projectPath);

  console.log(chalk.bold(`\n🔐 sphinx-agent — ${projectName}\n`));
  console.log(chalk.dim("━".repeat(60)));

  if (!result) {
    console.log(chalk.yellow("\n  No scan results. Run: sphinx-agent scan\n"));
    return;
  }

  const vulns = result.confirmedVulnerabilities;
  const counts = {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
  };

  // Trust score
  let score = 10;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        score -= 2;
        break;
      case "high":
        score -= 1;
        break;
      case "medium":
        score -= 0.5;
        break;
      case "low":
        score -= 0.2;
        break;
    }
  }
  score = Math.max(0, Math.min(10, score));
  const scoreColor = score >= 7 ? chalk.green : score >= 4 ? chalk.yellow : chalk.red;

  // Header row
  console.log(
    `\n  Trust Score  ${scoreColor.bold(`${score.toFixed(1)}/10`)}   |   Findings  ${chalk.bold(String(vulns.length))}   |   Chains  ${chalk.bold(String(result.chains.length))}   |   Suppressed  ${chalk.dim(String(suppressions.length))}`
  );
  console.log();

  // Severity breakdown
  const bar = (count: number, max: number, color: (s: string) => string) => {
    const width = max > 0 ? Math.max(1, Math.round((count / max) * 20)) : 0;
    return count > 0
      ? color("█".repeat(width)) + chalk.dim("░".repeat(20 - width))
      : chalk.dim("░".repeat(20));
  };
  const maxCount = Math.max(counts.critical, counts.high, counts.medium, counts.low, 1);

  console.log(
    `  Critical  ${String(counts.critical).padStart(3)}  ${bar(counts.critical, maxCount, chalk.red)}`
  );
  console.log(
    `  High      ${String(counts.high).padStart(3)}  ${bar(counts.high, maxCount, chalk.yellow)}`
  );
  console.log(
    `  Medium    ${String(counts.medium).padStart(3)}  ${bar(counts.medium, maxCount, chalk.blue)}`
  );
  console.log(
    `  Low       ${String(counts.low).padStart(3)}  ${bar(counts.low, maxCount, chalk.dim)}`
  );

  // Categories
  const categories = new Map<string, number>();
  for (const v of vulns) categories.set(v.category, (categories.get(v.category) || 0) + 1);
  const topCats = [...categories.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (topCats.length > 0) {
    console.log(chalk.bold("\n  Top Categories"));
    for (const [cat, count] of topCats) {
      console.log(chalk.dim(`    ${cat.padEnd(20)} ${count}`));
    }
  }

  // Trend
  if (history.scans.length >= 2) {
    const prev = history.scans[history.scans.length - 2];
    const curr = history.scans[history.scans.length - 1];
    const delta = curr.total - prev.total;
    const scoreDelta = curr.trustScore - prev.trustScore;
    console.log(chalk.bold("\n  Trend") + chalk.dim(` (vs previous scan)`));
    console.log(
      `    Findings: ${delta <= 0 ? chalk.green(`${delta}`) : chalk.red(`+${delta}`)}   Score: ${scoreDelta >= 0 ? chalk.green(`+${scoreDelta.toFixed(1)}`) : chalk.red(scoreDelta.toFixed(1))}`
    );
  }

  // Baseline
  if (result) {
    const diff = compareToBaseline(projectPath, result);
    if (diff) {
      console.log(chalk.bold("\n  Baseline Comparison"));
      console.log(
        `    New: ${diff.newFindings.length > 0 ? chalk.red(`+${diff.newFindings.length}`) : chalk.green("0")}   Fixed: ${diff.fixedFindings.length > 0 ? chalk.green(`-${diff.fixedFindings.length}`) : chalk.dim("0")}   Unchanged: ${diff.unchangedCount}`
      );
    }
  }

  // Policy
  const policy = loadPolicy(projectPath);
  if (policy && result) {
    const policyResult = evaluatePolicy(policy, result);
    console.log(chalk.bold("\n  Policy") + chalk.dim(` (${policy.name})`));
    console.log(
      `    Status: ${policyResult.passed ? chalk.green("PASSED") : chalk.red("FAILED")}   Violations: ${policyResult.violations.length}   Warnings: ${policyResult.warnings.length}`
    );
  }

  // Tools
  const installed = tools.filter((t) => t.installed);
  console.log(chalk.bold("\n  Tools") + chalk.dim(` (${installed.length}/${tools.length})`));
  console.log(
    `    ${installed.map((t) => chalk.green(t.name)).join("  ") || chalk.dim("none installed")}`
  );

  // Config
  console.log(chalk.bold("\n  Config"));
  console.log(chalk.dim(`    Provider: ${config.provider}   Model: ${config.model}`));
  console.log(
    chalk.dim(`    Config: ${configFile ? "yes" : "no"}   API key: ${config.apiKey ? "yes" : "no"}`)
  );

  // Quick actions
  console.log(chalk.bold("\n  Quick Actions"));
  if (counts.critical > 0)
    console.log(chalk.cyan("    sphinx-agent fix --severity critical --apply"));
  if (vulns.length > 0) console.log(chalk.cyan("    sphinx-agent plan"));
  if (!configFile) console.log(chalk.cyan("    sphinx-agent generate"));
  console.log(chalk.cyan("    sphinx-agent dashboard"));

  console.log();
}
