import path from "node:path";
import chalk from "chalk";
import { loadConfig } from "../../config/config.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import type { Vulnerability } from "../../types/index.js";

interface QuickOptions {
  path?: string;
}

export async function quickCommand(options: QuickOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);
  const start = Date.now();

  // Fast scan — patterns + secrets only
  const ps = new PatternScanner(config);
  const { findings: pf } = await ps.scan(projectPath);
  const ss = new SecretsScanner();
  const { findings: sf } = await ss.scan(projectPath);
  const all = [...pf, ...sf];
  const duration = Date.now() - start;

  // Trust score
  let score = 10;
  for (const v of all) {
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

  const counts = {
    critical: all.filter((v) => v.severity === "critical").length,
    high: all.filter((v) => v.severity === "high").length,
    medium: all.filter((v) => v.severity === "medium").length,
    low: all.filter((v) => v.severity === "low").length,
  };

  // One-line header
  console.log(
    chalk.bold(`\n🔐 `) +
      scoreColor.bold(`${score.toFixed(1)}/10`) +
      chalk.dim(` | `) +
      (counts.critical > 0 ? chalk.red(`${counts.critical}C `) : "") +
      (counts.high > 0 ? chalk.yellow(`${counts.high}H `) : "") +
      (counts.medium > 0 ? chalk.blue(`${counts.medium}M `) : "") +
      (counts.low > 0 ? chalk.dim(`${counts.low}L `) : "") +
      (all.length === 0 ? chalk.green("Clean! ") : "") +
      chalk.dim(`(${duration}ms)`)
  );

  if (all.length === 0) {
    console.log(chalk.green("\n  ✅ No issues found.\n"));
    return;
  }

  // Top 5 findings
  const top = all
    .sort((a, b) => {
      const order = ["critical", "high", "medium", "low", "info"];
      return order.indexOf(a.severity) - order.indexOf(b.severity);
    })
    .slice(0, 5);

  console.log();
  for (const f of top) {
    const icon =
      f.severity === "critical"
        ? "🔴"
        : f.severity === "high"
          ? "🟠"
          : f.severity === "medium"
            ? "🟡"
            : "🔵";
    console.log(`  ${icon} ${f.title}`);
    console.log(chalk.dim(`     ${f.location.file}:${f.location.line}`));
  }

  if (all.length > 5) {
    console.log(chalk.dim(`\n  ...and ${all.length - 5} more`));
  }

  // Suggested next action
  console.log();
  if (counts.critical > 0) {
    console.log(chalk.cyan("  → mythos-agent fix --severity critical --apply"));
  } else if (counts.high > 0) {
    console.log(chalk.cyan("  → mythos-agent fix --severity high --apply"));
  } else {
    console.log(chalk.cyan("  → mythos-agent scan  (for full analysis)"));
  }
  console.log();
}
