import chalk from "chalk";
import ora from "ora";
import { isTrivyInstalled, runTrivyImage } from "../../tools/trivy.js";
import { renderTerminalReport } from "../../report/terminal-reporter.js";
import type { Vulnerability, ScanResult } from "../../types/index.js";

interface ImageOptions {
  json?: boolean;
  severity?: string;
}

export async function imageCommand(imageName: string, options: ImageOptions) {
  console.log(chalk.bold("\n🐳 sphinx-agent image — Container Security Scan\n"));
  console.log(chalk.dim(`  Image: ${imageName}\n`));

  if (!isTrivyInstalled()) {
    console.log(chalk.yellow("  ⚠️  Trivy required for image scanning."));
    console.log(chalk.dim("  Install: brew install trivy  # or: apt-get install trivy\n"));
    return;
  }

  const spinner = ora("Scanning container image...").start();
  const startTime = Date.now();

  try {
    const findings = runTrivyImage(imageName);
    const duration = Date.now() - startTime;

    spinner.succeed(`Scanned image in ${(duration / 1000).toFixed(1)}s — ${findings.length} findings`);

    if (findings.length === 0) {
      console.log(chalk.green("\n  ✅ No vulnerabilities found in image.\n"));
      return;
    }

    // Filter by severity
    let filtered = findings;
    if (options.severity) {
      const order = ["critical", "high", "medium", "low", "info"];
      const threshold = order.indexOf(options.severity);
      filtered = findings.filter((f) => order.indexOf(f.severity) <= threshold);
    }

    const result: ScanResult = {
      projectPath: imageName,
      timestamp: new Date().toISOString(),
      duration,
      languages: [],
      filesScanned: 0,
      phase1Findings: filtered,
      phase2Findings: [],
      confirmedVulnerabilities: filtered,
      dismissedCount: 0,
      chains: [],
    };

    if (options.json) {
      console.log(JSON.stringify({
        image: imageName,
        findings: filtered.length,
        critical: filtered.filter((f) => f.severity === "critical").length,
        high: filtered.filter((f) => f.severity === "high").length,
        medium: filtered.filter((f) => f.severity === "medium").length,
        low: filtered.filter((f) => f.severity === "low").length,
      }, null, 2));
    } else {
      renderTerminalReport(result);
    }
  } catch (err) {
    spinner.fail(`Image scan failed: ${err instanceof Error ? err.message : "error"}`);
  }
}
