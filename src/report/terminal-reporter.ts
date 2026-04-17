import chalk from "chalk";
import type { ScanResult, Severity, Vulnerability, VulnChain } from "../types/index.js";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.dim,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "!!!",
  high: " ! ",
  medium: " ~ ",
  low: " - ",
  info: " . ",
};

export function renderTerminalReport(result: ScanResult): void {
  const { confirmedVulnerabilities: vulns, chains, dismissedCount } = result;

  console.log(chalk.dim("\n" + "━".repeat(50)));

  // Chains first (most important)
  if (chains.length > 0) {
    console.log(chalk.bold.red("\n⛓️  VULNERABILITY CHAINS\n"));
    for (const chain of chains) {
      renderChain(chain);
    }
  }

  // Individual vulnerabilities
  if (vulns.length > 0) {
    console.log(chalk.bold("\n🔍 VULNERABILITIES\n"));

    // Group by severity
    const bySeverity = groupBySeverity(vulns);
    for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
      const group = bySeverity.get(severity);
      if (!group || group.length === 0) continue;

      console.log(
        SEVERITY_COLORS[severity](` ${severity.toUpperCase()} (${group.length}) `) + "\n"
      );

      for (const vuln of group) {
        renderVulnerability(vuln);
      }
    }
  }

  // Summary
  console.log(chalk.dim("━".repeat(50)));
  renderSummary(result);
}

function renderChain(chain: VulnChain): void {
  const color = SEVERITY_COLORS[chain.severity];
  console.log(color(` ${chain.severity.toUpperCase()} `) + " " + chalk.bold(chain.title));

  for (let i = 0; i < chain.vulnerabilities.length; i++) {
    const v = chain.vulnerabilities[i];
    const prefix = i === chain.vulnerabilities.length - 1 ? "  └──" : "  ├──";
    console.log(
      chalk.dim(prefix) +
        ` ${chalk.cyan(v.location.file)}:${chalk.yellow(String(v.location.line))}` +
        chalk.dim(` — ${v.title}`)
    );
  }

  console.log(chalk.dim("  →  ") + chalk.italic(chain.narrative));
  console.log(chalk.dim("  💥 Impact: ") + chain.impact);
  console.log();
}

function renderVulnerability(vuln: Vulnerability): void {
  const icon = vuln.aiVerified ? "✓" : "?";
  const verified = vuln.aiVerified ? chalk.green(" AI-verified") : chalk.dim(" pattern-match");

  console.log(`  ${chalk.dim(vuln.id)} ${chalk.bold(vuln.title)}${verified}`);
  console.log(
    `    ${chalk.cyan(vuln.location.file)}:${chalk.yellow(String(vuln.location.line))}` +
      (vuln.cwe ? chalk.dim(` (${vuln.cwe})`) : "")
  );
  if (vuln.location.snippet) {
    console.log(chalk.dim(`    > ${vuln.location.snippet}`));
  }
  console.log();
}

function renderSummary(result: ScanResult): void {
  const { confirmedVulnerabilities: vulns, chains, dismissedCount } = result;
  const duration = (result.duration / 1000).toFixed(1);

  const counts = {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
  };

  console.log(chalk.bold("\n📊 Summary\n"));
  console.log(`  Files scanned:  ${chalk.bold(String(result.filesScanned))}`);
  console.log(`  Languages:      ${result.languages.join(", ") || "none detected"}`);
  console.log(`  Scan time:      ${duration}s`);
  console.log();

  console.log(
    `  Vulnerabilities: ${chalk.bold(String(vulns.length))}` +
      (dismissedCount > 0 ? chalk.dim(` (${dismissedCount} false positives dismissed by AI)`) : "")
  );

  if (vulns.length > 0) {
    const parts: string[] = [];
    if (counts.critical > 0) parts.push(chalk.bgRed.white.bold(` ${counts.critical} CRITICAL `));
    if (counts.high > 0) parts.push(chalk.red.bold(`${counts.high} High`));
    if (counts.medium > 0) parts.push(chalk.yellow.bold(`${counts.medium} Medium`));
    if (counts.low > 0) parts.push(chalk.blue(`${counts.low} Low`));
    console.log(`  Breakdown:      ${parts.join("  ")}`);
  }

  if (chains.length > 0) {
    console.log(`  Attack chains:  ${chalk.red.bold(String(chains.length))}`);
  }

  // Trust score
  const score = calculateTrustScore(vulns, chains);
  const scoreColor = score >= 8 ? chalk.green : score >= 5 ? chalk.yellow : chalk.red;
  console.log(
    `\n  Trust Score:    ${scoreColor(`${score.toFixed(1)}/10`)}` +
      chalk.dim(
        score >= 8
          ? " — looking good"
          : score >= 5
            ? " — review recommended"
            : " — critical issues found"
      )
  );

  console.log();
}

function calculateTrustScore(vulns: Vulnerability[], chains: VulnChain[]): number {
  let score = 10;

  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        score -= 2.0;
        break;
      case "high":
        score -= 1.0;
        break;
      case "medium":
        score -= 0.5;
        break;
      case "low":
        score -= 0.2;
        break;
    }
  }

  // Chains are extra bad
  for (const chain of chains) {
    switch (chain.severity) {
      case "critical":
        score -= 1.5;
        break;
      case "high":
        score -= 1.0;
        break;
      default:
        score -= 0.5;
    }
  }

  return Math.max(0, Math.min(10, score));
}

function groupBySeverity(vulns: Vulnerability[]): Map<Severity, Vulnerability[]> {
  const map = new Map<Severity, Vulnerability[]>();
  for (const v of vulns) {
    const list = map.get(v.severity) || [];
    list.push(v);
    map.set(v.severity, list);
  }
  return map;
}
