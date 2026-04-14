import path from "node:path";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";
import {
  saveBaseline,
  loadBaseline,
  compareToBaseline,
} from "../../store/baseline.js";

export async function baselineSaveCommand(options: { path?: string }) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(
      chalk.yellow(
        "\n⚠️  No scan results. Run " +
          chalk.cyan("sphinx-agent scan") +
          " first.\n"
      )
    );
    return;
  }

  const baselinePath = saveBaseline(projectPath, result);
  console.log(
    chalk.green(
      `\n✅ Baseline saved (${result.confirmedVulnerabilities.length} findings) to ${baselinePath}\n`
    )
  );
  console.log(
    chalk.dim("  Future scans can compare against this baseline:\n") +
      chalk.cyan("  sphinx-agent baseline compare\n")
  );
}

export async function baselineCompareCommand(options: {
  path?: string;
  json?: boolean;
}) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(
      chalk.yellow(
        "\n⚠️  No scan results. Run " +
          chalk.cyan("sphinx-agent scan") +
          " first.\n"
      )
    );
    return;
  }

  const baseline = loadBaseline(projectPath);
  if (!baseline) {
    console.log(
      chalk.yellow(
        "\n⚠️  No baseline saved. Run " +
          chalk.cyan("sphinx-agent baseline save") +
          " first.\n"
      )
    );
    return;
  }

  const diff = compareToBaseline(projectPath, result);
  if (!diff) return;

  if (options.json) {
    console.log(
      JSON.stringify({
        baselineDate: baseline.timestamp,
        newFindings: diff.newFindings.length,
        fixedFindings: diff.fixedFindings.length,
        unchanged: diff.unchangedCount,
      }, null, 2)
    );
    return;
  }

  console.log(chalk.bold("\n📊 sphinx-agent baseline comparison\n"));
  console.log(chalk.dim("━".repeat(50)));
  console.log(
    chalk.dim(`  Baseline: ${new Date(baseline.timestamp).toLocaleString()} (${baseline.findings.length} findings)`)
  );
  console.log(
    chalk.dim(`  Current:  ${new Date(result.timestamp).toLocaleString()} (${result.confirmedVulnerabilities.length} findings)`)
  );
  console.log();

  // New findings (regressions)
  if (diff.newFindings.length > 0) {
    console.log(
      chalk.red.bold(`  🔺 ${diff.newFindings.length} NEW finding(s) (regressions):\n`)
    );
    for (const f of diff.newFindings.slice(0, 20)) {
      console.log(
        `    ${severityIcon(f.severity)} ${chalk.bold(f.title)}`
      );
      console.log(chalk.dim(`      ${f.location.file}:${f.location.line}`));
    }
    console.log();
  }

  // Fixed findings (improvements)
  if (diff.fixedFindings.length > 0) {
    console.log(
      chalk.green.bold(`  🔽 ${diff.fixedFindings.length} FIXED finding(s):\n`)
    );
    for (const f of diff.fixedFindings.slice(0, 20)) {
      console.log(
        `    ${chalk.green("✓")} ${chalk.strikethrough(f.title)}`
      );
      console.log(chalk.dim(`      ${f.file}:${f.line}`));
    }
    console.log();
  }

  // Summary
  console.log(chalk.dim(`  ${diff.unchangedCount} unchanged findings\n`));

  if (diff.newFindings.length === 0 && diff.fixedFindings.length > 0) {
    console.log(chalk.green.bold("  ✅ Security improved! No new issues introduced.\n"));
  } else if (diff.newFindings.length > 0) {
    console.log(
      chalk.red.bold(`  ⚠️  ${diff.newFindings.length} regressions detected. Review before merging.\n`)
    );
  } else {
    console.log(chalk.dim("  No changes since baseline.\n"));
  }
}

function severityIcon(s: string): string {
  switch (s) {
    case "critical": return "🔴";
    case "high": return "🟠";
    case "medium": return "🟡";
    case "low": return "🔵";
    default: return "⚪";
  }
}
