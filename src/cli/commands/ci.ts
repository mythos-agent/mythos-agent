import path from "node:path";
import fs from "node:fs";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import { DepScanner } from "../../scanner/dep-scanner.js";
import { IacScanner } from "../../scanner/iac-scanner.js";
import { runAllTools } from "../../tools/index.js";
import { loadPolicy, evaluatePolicy } from "../../policy/engine.js";
import { renderSarifReport } from "../../report/sarif-reporter.js";
import { saveResults } from "../../store/results-store.js";
import type { Vulnerability, ScanResult, Severity } from "../../types/index.js";

interface CiOptions {
  path?: string;
  failOn: string;
  sarif?: string;
  json?: boolean;
}

/**
 * One command for CI/CD: scan + policy check + SARIF output.
 * Designed to be the only command needed in a CI pipeline.
 */
export async function ciCommand(options: CiOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);
  const startTime = Date.now();

  console.log(chalk.bold("🔐 shedu ci\n"));

  // Run all scanners
  const spinner = ora("Scanning...").start();
  const allFindings: Vulnerability[] = [];

  // Built-in scanners
  const patternScanner = new PatternScanner(config);
  const { findings: patterns } = await patternScanner.scan(projectPath);
  allFindings.push(...patterns);

  const secretsScanner = new SecretsScanner();
  const { findings: secrets } = await secretsScanner.scan(projectPath);
  allFindings.push(...secrets);

  try {
    const depScanner = new DepScanner();
    const { findings: deps } = await depScanner.scan(projectPath);
    allFindings.push(...deps);
  } catch {
    /* optional */
  }

  const iacScanner = new IacScanner();
  const { findings: iac } = await iacScanner.scan(projectPath);
  allFindings.push(...iac);

  // External tools
  const { findings: external, toolsRun } = await runAllTools(projectPath);
  allFindings.push(...external);

  spinner.succeed(
    `Found ${allFindings.length} findings` +
      (toolsRun.length > 0 ? ` (tools: ${toolsRun.join(", ")})` : "")
  );

  const duration = Date.now() - startTime;

  // Build result
  const result: ScanResult = {
    projectPath,
    timestamp: new Date().toISOString(),
    duration,
    languages: [],
    filesScanned: 0,
    phase1Findings: allFindings,
    phase2Findings: [],
    confirmedVulnerabilities: allFindings,
    dismissedCount: 0,
    chains: [],
  };

  saveResults(projectPath, result);

  // SARIF output
  if (options.sarif) {
    const sarifOutput = renderSarifReport(result);
    const sarifPath = path.resolve(options.sarif);
    fs.mkdirSync(path.dirname(sarifPath), { recursive: true });
    fs.writeFileSync(sarifPath, sarifOutput, "utf-8");
    console.log(chalk.dim(`  SARIF: ${sarifPath}`));
  }

  // Policy check
  const policy = loadPolicy(projectPath);
  if (policy) {
    const policyResult = evaluatePolicy(policy, result);
    if (!policyResult.passed) {
      console.log(
        chalk.red.bold(
          `\n  ❌ Policy "${policy.name}" FAILED — ${policyResult.violations.length} violation(s)\n`
        )
      );
      for (const v of policyResult.violations) {
        console.log(
          chalk.red(
            `    BLOCK ${v.ruleId}: ${v.description} (${v.matchedFindings.length} findings)`
          )
        );
      }
      process.exit(1);
    } else {
      console.log(chalk.green(`  ✅ Policy "${policy.name}" passed`));
    }
  }

  // Fail-on severity check
  const failOn = options.failOn;
  if (failOn !== "none") {
    const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
    const threshold = severityOrder.indexOf(failOn as Severity);
    const failing = allFindings.filter((f) => severityOrder.indexOf(f.severity) <= threshold);
    if (failing.length > 0) {
      const counts = {
        critical: failing.filter((f) => f.severity === "critical").length,
        high: failing.filter((f) => f.severity === "high").length,
        medium: failing.filter((f) => f.severity === "medium").length,
        low: failing.filter((f) => f.severity === "low").length,
      };
      const parts: string[] = [];
      if (counts.critical) parts.push(`${counts.critical} critical`);
      if (counts.high) parts.push(`${counts.high} high`);
      if (counts.medium) parts.push(`${counts.medium} medium`);
      if (counts.low) parts.push(`${counts.low} low`);

      console.log(
        chalk.red.bold(
          `\n  ❌ ${failing.length} findings at ${failOn} or above: ${parts.join(", ")}\n`
        )
      );
      process.exit(1);
    }
  }

  // Summary
  const counts = {
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
  };

  console.log(
    chalk.dim(
      `\n  ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low (${(duration / 1000).toFixed(1)}s)\n`
    )
  );

  if (options.json) {
    console.log(
      JSON.stringify({
        findings: allFindings.length,
        ...counts,
        duration,
      })
    );
  }
}
