import path from "node:path";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";
import {
  generateComplianceReport,
  saveComplianceReport,
} from "../../report/compliance-reporter.js";

interface ComplianceOptions {
  path?: string;
  frameworks: string;
  json?: boolean;
  output?: string;
}

export async function complianceCommand(options: ComplianceOptions) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(chalk.yellow("\n⚠️  No scan results. Run sphinx-agent scan first.\n"));
    return;
  }

  const frameworks = options.frameworks.split(",").map((f) => f.trim().toUpperCase());
  const validFrameworks = ["SOC2", "HIPAA", "PCI-DSS", "OWASP"];
  const selectedFrameworks = frameworks.filter((f) => validFrameworks.includes(f));

  if (selectedFrameworks.length === 0) {
    console.log(
      chalk.yellow(`\n⚠️  No valid frameworks. Choose from: ${validFrameworks.join(", ")}\n`)
    );
    return;
  }

  const reports = generateComplianceReport(result, selectedFrameworks);

  if (options.json) {
    console.log(JSON.stringify(reports, null, 2));
    return;
  }

  // Always save the report file
  const outputPath = saveComplianceReport(result, selectedFrameworks, projectPath);
  console.log(chalk.green(`\n✅ Compliance report saved to ${outputPath}\n`));

  // Terminal summary
  console.log(chalk.bold("\n📋 Compliance Summary\n"));

  for (const report of reports) {
    const passColor =
      report.passRate >= 80 ? chalk.green : report.passRate >= 60 ? chalk.yellow : chalk.red;
    console.log(
      `  ${chalk.bold(report.framework.padEnd(10))} ` +
        passColor(`${report.passRate}% pass rate`) +
        chalk.dim(` (${report.controls.length} controls)`)
    );

    const failed = report.controls.filter((c) => c.status === "fail");
    const partial = report.controls.filter((c) => c.status === "partial");

    if (failed.length > 0) {
      console.log(
        chalk.red(`    ❌ ${failed.length} failed: ${failed.map((c) => c.controlId).join(", ")}`)
      );
    }
    if (partial.length > 0) {
      console.log(
        chalk.yellow(
          `    ⚠️  ${partial.length} partial: ${partial.map((c) => c.controlId).join(", ")}`
        )
      );
    }
    console.log();
  }
}
