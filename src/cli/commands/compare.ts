import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import type { Vulnerability } from "../../types/index.js";

interface CompareOptions {
  json?: boolean;
}

export async function compareCommand(
  pathA: string,
  pathB: string,
  options: CompareOptions
) {
  const dirA = path.resolve(pathA);
  const dirB = path.resolve(pathB);
  const nameA = path.basename(dirA);
  const nameB = path.basename(dirB);

  console.log(chalk.bold("\n⚖️  sphinx-agent compare\n"));
  console.log(chalk.dim(`  A: ${dirA}`));
  console.log(chalk.dim(`  B: ${dirB}\n`));

  const spinner = ora("Scanning both targets...").start();

  // Scan both in parallel
  const [resultA, resultB] = await Promise.all([
    scanQuick(dirA),
    scanQuick(dirB),
  ]);

  spinner.stop();

  const countA = countBySeverity(resultA);
  const countB = countBySeverity(resultB);
  const scoreA = trustScore(resultA);
  const scoreB = trustScore(resultB);

  if (options.json) {
    console.log(JSON.stringify({
      a: { path: dirA, findings: resultA.length, ...countA, trustScore: scoreA },
      b: { path: dirB, findings: resultB.length, ...countB, trustScore: scoreB },
      delta: {
        findings: resultB.length - resultA.length,
        critical: countB.critical - countA.critical,
        high: countB.high - countA.high,
        trustScore: +(scoreB - scoreA).toFixed(1),
      },
    }, null, 2));
    return;
  }

  // Side-by-side comparison table
  console.log(chalk.bold("  Comparison Results\n"));

  const col1 = 20;
  const col2 = 15;

  const header = `  ${"Metric".padEnd(col1)} ${nameA.padStart(col2)} ${nameB.padStart(col2)} ${"Delta".padStart(col2)}`;
  console.log(chalk.dim(header));
  console.log(chalk.dim("  " + "─".repeat(col1 + col2 * 3 + 3)));

  printRow("Trust Score", fmtScore(scoreA), fmtScore(scoreB), fmtDelta(scoreB - scoreA, true), col1, col2);
  printRow("Total Findings", String(resultA.length), String(resultB.length), fmtDelta(resultB.length - resultA.length, false), col1, col2);
  printRow("Critical", String(countA.critical), String(countB.critical), fmtDelta(countB.critical - countA.critical, false), col1, col2);
  printRow("High", String(countA.high), String(countB.high), fmtDelta(countB.high - countA.high, false), col1, col2);
  printRow("Medium", String(countA.medium), String(countB.medium), fmtDelta(countB.medium - countA.medium, false), col1, col2);
  printRow("Low", String(countA.low), String(countB.low), fmtDelta(countB.low - countA.low, false), col1, col2);

  console.log();

  // Unique findings
  const fpA = new Set(resultA.map(fingerprint));
  const fpB = new Set(resultB.map(fingerprint));

  const onlyInA = resultA.filter((v) => !fpB.has(fingerprint(v)));
  const onlyInB = resultB.filter((v) => !fpA.has(fingerprint(v)));

  if (onlyInA.length > 0) {
    console.log(chalk.green(`  ✅ Only in ${nameA} (${onlyInA.length} — fixed in ${nameB}):\n`));
    for (const v of onlyInA.slice(0, 10)) {
      console.log(chalk.dim(`    ${severityIcon(v.severity)} ${v.title} — ${v.location.file}:${v.location.line}`));
    }
    console.log();
  }

  if (onlyInB.length > 0) {
    console.log(chalk.red(`  🔺 Only in ${nameB} (${onlyInB.length} — new regressions):\n`));
    for (const v of onlyInB.slice(0, 10)) {
      console.log(chalk.dim(`    ${severityIcon(v.severity)} ${v.title} — ${v.location.file}:${v.location.line}`));
    }
    console.log();
  }

  if (onlyInA.length === 0 && onlyInB.length === 0) {
    console.log(chalk.dim("  Both targets have identical findings.\n"));
  }

  // Verdict
  if (scoreB > scoreA) {
    console.log(chalk.green.bold(`  ✅ ${nameB} is more secure than ${nameA}\n`));
  } else if (scoreB < scoreA) {
    console.log(chalk.red.bold(`  ⚠️  ${nameA} is more secure than ${nameB}\n`));
  } else {
    console.log(chalk.dim(`  Both have the same trust score.\n`));
  }
}

async function scanQuick(dir: string): Promise<Vulnerability[]> {
  const config = loadConfig(dir);
  const findings: Vulnerability[] = [];

  const ps = new PatternScanner(config);
  const { findings: pf } = await ps.scan(dir, false);
  findings.push(...pf);

  const ss = new SecretsScanner();
  const { findings: sf } = await ss.scan(dir);
  findings.push(...sf);

  return findings;
}

function countBySeverity(vulns: Vulnerability[]) {
  return {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
  };
}

function trustScore(vulns: Vulnerability[]): number {
  let s = 10;
  for (const v of vulns) {
    switch (v.severity) { case "critical": s -= 2; break; case "high": s -= 1; break; case "medium": s -= 0.5; break; case "low": s -= 0.2; break; }
  }
  return Math.max(0, Math.min(10, s));
}

function fingerprint(v: Vulnerability): string {
  return `${v.rule}:${v.location.file}:${Math.floor(v.location.line / 5) * 5}`;
}

function fmtScore(s: number): string {
  return `${s.toFixed(1)}/10`;
}

function fmtDelta(d: number, higherIsBetter: boolean): string {
  if (d === 0) return chalk.dim("  —");
  const arrow = d > 0 ? "▲" : "▼";
  const color = (higherIsBetter ? d > 0 : d < 0) ? chalk.green : chalk.red;
  return color(`${arrow}${Math.abs(d).toFixed(d % 1 === 0 ? 0 : 1)}`);
}

function printRow(label: string, a: string, b: string, delta: string, c1: number, c2: number) {
  console.log(`  ${label.padEnd(c1)} ${a.padStart(c2)} ${b.padStart(c2)} ${delta.padStart(c2 + 10)}`);
}

function severityIcon(s: string): string {
  switch (s) { case "critical": return "🔴"; case "high": return "🟠"; case "medium": return "🟡"; default: return "🔵"; }
}
