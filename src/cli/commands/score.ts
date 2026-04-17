import path from "node:path";
import fs from "node:fs";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";
import { loadResults } from "../../store/results-store.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import { DepScanner } from "../../scanner/dep-scanner.js";
import { IacScanner } from "../../scanner/iac-scanner.js";
import { checkAllTools } from "../../tools/index.js";
import { discoverLockfiles } from "../../scanner/lockfile-parsers.js";
import type { Vulnerability } from "../../types/index.js";

interface ScoreOptions {
  path?: string;
  badge?: boolean;
  json?: boolean;
}

interface ScoreBreakdown {
  category: string;
  score: number;
  maxScore: number;
  details: string;
}

export async function scoreCommand(options: ScoreOptions) {
  const projectPath = path.resolve(options.path || ".");

  if (!options.json) {
    console.log(chalk.bold("\n🏆 sphinx-agent security scorecard\n"));
  }

  const spinner = options.json ? null : ora("Analyzing security posture...").start();

  // Run a quick scan
  const config = loadConfig(projectPath);
  const findings: Vulnerability[] = [];

  const ps = new PatternScanner(config);
  const { findings: pf, filesScanned } = await ps.scan(projectPath);
  findings.push(...pf);

  const ss = new SecretsScanner();
  const { findings: sf } = await ss.scan(projectPath);
  findings.push(...sf);

  const iacScanner = new IacScanner();
  const { findings: iacf } = await iacScanner.scan(projectPath);
  findings.push(...iacf);

  let depVulns = 0;
  try {
    const ds = new DepScanner();
    const { findings: df } = await ds.scan(projectPath);
    findings.push(...df);
    depVulns = df.length;
  } catch {
    /* optional */
  }

  if (spinner) spinner.stop();

  // Calculate score breakdown
  const breakdown: ScoreBreakdown[] = [];
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };

  // Code security (30 points)
  let codeScore = 30;
  codeScore -= counts.critical * 10;
  codeScore -= counts.high * 5;
  codeScore -= counts.medium * 2;
  codeScore -= counts.low * 0.5;
  codeScore = Math.max(0, codeScore);
  breakdown.push({
    category: "Code Security",
    score: Math.round(codeScore),
    maxScore: 30,
    details: `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`,
  });

  // Secrets (20 points)
  const secretCount = findings.filter((f) => f.category === "secrets").length;
  const secretScore = secretCount === 0 ? 20 : Math.max(0, 20 - secretCount * 10);
  breakdown.push({
    category: "Secrets Management",
    score: secretScore,
    maxScore: 20,
    details: secretCount === 0 ? "No hardcoded secrets found" : `${secretCount} secrets detected`,
  });

  // Dependencies (20 points)
  const lockfiles = discoverLockfiles(projectPath);
  const depScore =
    lockfiles.length > 0 ? (depVulns === 0 ? 20 : Math.max(0, 20 - depVulns * 3)) : 10;
  breakdown.push({
    category: "Dependencies",
    score: depScore,
    maxScore: 20,
    details:
      lockfiles.length > 0
        ? depVulns === 0
          ? "All dependencies clean"
          : `${depVulns} vulnerable dependencies`
        : "No lockfile (partially scored)",
  });

  // Infrastructure (15 points)
  const iacCount = findings.filter((f) => f.category === "iac").length;
  const iacScore = iacCount === 0 ? 15 : Math.max(0, 15 - iacCount * 3);
  breakdown.push({
    category: "Infrastructure",
    score: iacScore,
    maxScore: 15,
    details: iacCount === 0 ? "No IaC misconfigs found" : `${iacCount} misconfigurations`,
  });

  // Tooling & practices (15 points)
  let toolScore = 0;
  const tools = checkAllTools();
  const installedTools = tools.filter((t) => t.installed).length;
  toolScore += Math.min(5, installedTools * 1); // up to 5 for tools

  if (fs.existsSync(path.join(projectPath, ".sphinx.yml"))) toolScore += 3;
  if (fs.existsSync(path.join(projectPath, ".sphinx", "policy.yml"))) toolScore += 3;
  if (fs.existsSync(path.join(projectPath, ".gitignore"))) toolScore += 2;
  if (fs.existsSync(path.join(projectPath, ".github", "workflows"))) toolScore += 2;

  breakdown.push({
    category: "Tooling & Practices",
    score: Math.min(15, toolScore),
    maxScore: 15,
    details: `${installedTools} tools, ${toolScore >= 8 ? "good" : "needs improvement"} security practices`,
  });

  // Total
  const totalScore = breakdown.reduce((s, b) => s + b.score, 0);
  const maxScore = breakdown.reduce((s, b) => s + b.maxScore, 0);
  const grade =
    totalScore >= 90
      ? "A+"
      : totalScore >= 80
        ? "A"
        : totalScore >= 70
          ? "B"
          : totalScore >= 60
            ? "C"
            : totalScore >= 50
              ? "D"
              : "F";

  if (options.json) {
    console.log(JSON.stringify({ score: totalScore, maxScore, grade, breakdown }, null, 2));
    return;
  }

  // Render scorecard
  console.log(chalk.dim("━".repeat(50)));

  for (const b of breakdown) {
    const pct = Math.round((b.score / b.maxScore) * 100);
    const barLen = 20;
    const filled = Math.round((pct / 100) * barLen);
    const bar = "█".repeat(filled) + "░".repeat(barLen - filled);
    const color = pct >= 80 ? chalk.green : pct >= 50 ? chalk.yellow : chalk.red;

    console.log(`\n  ${chalk.bold(b.category.padEnd(22))} ${color(bar)} ${b.score}/${b.maxScore}`);
    console.log(chalk.dim(`  ${b.details}`));
  }

  const gradeColor = totalScore >= 70 ? chalk.green : totalScore >= 50 ? chalk.yellow : chalk.red;
  console.log("\n" + chalk.dim("━".repeat(50)));
  console.log(
    chalk.bold(`\n  Overall Score: `) +
      gradeColor.bold(`${totalScore}/${maxScore} (${grade})`) +
      "\n"
  );

  // Badge
  if (options.badge) {
    const badgeColor = totalScore >= 70 ? "brightgreen" : totalScore >= 50 ? "yellow" : "red";
    const badgeUrl = `https://img.shields.io/badge/security-${grade}%20(${totalScore}%25)-${badgeColor}`;
    const badgeMd = `[![Security Score](${badgeUrl})](https://github.com/sphinx-agent/sphinx-agent)`;

    console.log(chalk.bold("  README Badge:\n"));
    console.log(chalk.cyan(`  ${badgeMd}`));
    console.log();

    // Save badge markdown
    const badgePath = path.join(projectPath, ".sphinx", "badge.md");
    const dir = path.dirname(badgePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(badgePath, badgeMd + "\n");
    console.log(chalk.dim(`  Saved to ${badgePath}\n`));
  }
}
