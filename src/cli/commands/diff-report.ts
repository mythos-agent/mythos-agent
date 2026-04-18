import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import { getGitChangedFiles } from "../../scanner/diff-scanner.js";
import { renderMarkdownReport, saveMarkdownReport } from "../../report/markdown-reporter.js";
import { saveResults } from "../../store/results-store.js";
import type { Vulnerability, ScanResult } from "../../types/index.js";

interface DiffReportOptions {
  path?: string;
  base: string;
  md?: boolean;
  json?: boolean;
}

export async function diffReportCommand(options: DiffReportOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);

  console.log(chalk.bold("\n📝 shedu diff-report\n"));
  console.log(chalk.dim(`  Base: ${options.base}`));
  console.log(chalk.dim(`  Path: ${projectPath}\n`));

  // Get changed files
  const changedFiles = getGitChangedFiles(projectPath, options.base);
  if (changedFiles.length === 0) {
    console.log(chalk.green("  ✅ No changed files.\n"));
    return;
  }

  console.log(chalk.dim(`  ${changedFiles.length} changed file(s):\n`));
  for (const f of changedFiles.slice(0, 15)) {
    const icon =
      f.status === "added"
        ? chalk.green("+")
        : f.status === "deleted"
          ? chalk.red("-")
          : chalk.yellow("~");
    console.log(`    ${icon} ${f.file}`);
  }
  if (changedFiles.length > 15)
    console.log(chalk.dim(`    ...and ${changedFiles.length - 15} more`));
  console.log();

  // Scan only changed files
  const spinner = ora("Scanning changed files...").start();

  const changedConfig = {
    ...config,
    scan: { ...config.scan, include: changedFiles.map((f) => f.file), exclude: [] },
  };

  const findings: Vulnerability[] = [];

  const ps = new PatternScanner(changedConfig);
  const { findings: pf, filesScanned, languages } = await ps.scan(projectPath, false);
  findings.push(...pf);

  const ss = new SecretsScanner();
  const { findings: sf } = await ss.scan(projectPath);
  // Filter secrets to changed files only
  const changedSet = new Set(changedFiles.map((f) => f.file));
  findings.push(...sf.filter((f) => changedSet.has(f.location.file)));

  spinner.succeed(`Found ${findings.length} finding(s) in ${changedFiles.length} changed files`);

  if (findings.length === 0) {
    console.log(chalk.green("\n  ✅ No security issues in changed files.\n"));
    return;
  }

  // Build result
  const result: ScanResult = {
    projectPath,
    timestamp: new Date().toISOString(),
    duration: 0,
    languages,
    filesScanned,
    phase1Findings: findings,
    phase2Findings: [],
    confirmedVulnerabilities: findings,
    dismissedCount: 0,
    chains: [],
  };

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          base: options.base,
          changedFiles: changedFiles.length,
          findings: findings.length,
          vulnerabilities: findings.map((f) => ({
            id: f.id,
            severity: f.severity,
            title: f.title,
            file: f.location.file,
            line: f.location.line,
          })),
        },
        null,
        2
      )
    );
    return;
  }

  if (options.md) {
    const mdPath = saveMarkdownReport(result, projectPath);
    console.log(chalk.green(`\n  ✅ Diff report saved to ${mdPath}\n`));
    return;
  }

  // Terminal output
  console.log();
  const bySeverity = new Map<string, Vulnerability[]>();
  for (const f of findings) {
    const list = bySeverity.get(f.severity) || [];
    list.push(f);
    bySeverity.set(f.severity, list);
  }

  for (const severity of ["critical", "high", "medium", "low"]) {
    const group = bySeverity.get(severity);
    if (!group || group.length === 0) continue;

    const color =
      severity === "critical"
        ? chalk.red
        : severity === "high"
          ? chalk.yellow
          : severity === "medium"
            ? chalk.blue
            : chalk.dim;
    console.log(color.bold(`  ${severity.toUpperCase()} (${group.length})\n`));

    for (const f of group) {
      console.log(`    ${f.id} ${f.title}`);
      console.log(chalk.dim(`      ${f.location.file}:${f.location.line}`));
    }
    console.log();
  }
}
