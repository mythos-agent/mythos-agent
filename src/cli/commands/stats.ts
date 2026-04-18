import path from "node:path";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";
import { loadHistory } from "../../store/history.js";
import { loadBaseline } from "../../store/baseline.js";
import { loadSuppressions } from "../../store/suppressions.js";
import { checkAllTools } from "../../tools/index.js";
import { findConfigFile } from "../../config/config.js";

interface StatsOptions {
  path?: string;
}

export async function statsCommand(options: StatsOptions) {
  const projectPath = path.resolve(options.path || ".");
  const projectName = path.basename(projectPath);

  console.log(chalk.bold(`\n📈 mythos-agent stats — ${projectName}\n`));

  // Latest scan
  const result = loadResults(projectPath);
  if (result) {
    const vulns = result.confirmedVulnerabilities;
    const counts = {
      critical: vulns.filter((v) => v.severity === "critical").length,
      high: vulns.filter((v) => v.severity === "high").length,
      medium: vulns.filter((v) => v.severity === "medium").length,
      low: vulns.filter((v) => v.severity === "low").length,
    };

    console.log(chalk.bold("  Latest Scan"));
    console.log(chalk.dim(`    Date: ${new Date(result.timestamp).toLocaleString()}`));
    console.log(chalk.dim(`    Duration: ${(result.duration / 1000).toFixed(1)}s`));
    console.log(chalk.dim(`    Files: ${result.filesScanned}`));
    console.log(
      `    Findings: ${chalk.bold(String(vulns.length))} (${chalk.red(`${counts.critical}C`)} ${chalk.yellow(`${counts.high}H`)} ${chalk.blue(`${counts.medium}M`)} ${chalk.dim(`${counts.low}L`)})`
    );
    console.log(`    Chains: ${result.chains.length}`);
    console.log(`    Dismissed: ${result.dismissedCount}`);
  } else {
    console.log(chalk.dim("  No scan results yet. Run: mythos-agent scan\n"));
  }

  // History
  const history = loadHistory(projectPath);
  if (history.scans.length > 0) {
    const latest = history.scans[history.scans.length - 1];
    const first = history.scans[0];
    const scoreDelta = latest.trustScore - first.trustScore;
    const findingsDelta = latest.total - first.total;

    console.log(chalk.bold("\n  Scan History"));
    console.log(chalk.dim(`    Total scans: ${history.scans.length}`));
    console.log(chalk.dim(`    First scan: ${new Date(first.timestamp).toLocaleDateString()}`));
    console.log(
      `    Trust score trend: ${first.trustScore.toFixed(1)} → ${latest.trustScore.toFixed(1)} (${scoreDelta >= 0 ? chalk.green(`+${scoreDelta.toFixed(1)}`) : chalk.red(scoreDelta.toFixed(1))})`
    );
    console.log(
      `    Findings trend: ${first.total} → ${latest.total} (${findingsDelta <= 0 ? chalk.green(String(findingsDelta)) : chalk.red(`+${findingsDelta}`)})`
    );
  }

  // Baseline
  const baseline = loadBaseline(projectPath);
  if (baseline) {
    console.log(chalk.bold("\n  Baseline"));
    console.log(chalk.dim(`    Saved: ${new Date(baseline.timestamp).toLocaleDateString()}`));
    console.log(chalk.dim(`    Findings at baseline: ${baseline.findings.length}`));
  }

  // Suppressions
  const suppressions = loadSuppressions(projectPath);
  if (suppressions.length > 0) {
    console.log(chalk.bold("\n  Suppressions"));
    console.log(chalk.dim(`    Active: ${suppressions.length}`));
  }

  // Tools
  const tools = checkAllTools();
  const installed = tools.filter((t) => t.installed);
  console.log(chalk.bold("\n  Tools"));
  console.log(
    chalk.dim(
      `    Installed: ${installed.length}/${tools.length} (${installed.map((t) => t.name).join(", ") || "none"})`
    )
  );

  // Config
  const configFile = findConfigFile(projectPath);
  console.log(chalk.bold("\n  Config"));
  console.log(chalk.dim(`    Config file: ${configFile ? "yes" : "no"}`));
  console.log(chalk.dim(`    Policy: ${path.join(projectPath, ".sphinx", "policy.yml")}`));

  console.log();
}
