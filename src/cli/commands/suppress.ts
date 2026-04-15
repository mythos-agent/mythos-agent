import path from "node:path";
import chalk from "chalk";
import {
  loadSuppressions,
  addSuppression,
  removeSuppression,
} from "../../store/suppressions.js";
import { loadResults } from "../../store/results-store.js";

export async function suppressAddCommand(
  findingId: string,
  options: { path?: string; reason?: string }
) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(chalk.yellow("\n⚠️  No scan results. Run sphinx-agent scan first.\n"));
    return;
  }

  const finding = result.confirmedVulnerabilities.find(
    (v) => v.id.toLowerCase() === findingId.toLowerCase()
  );

  if (!finding) {
    console.log(chalk.yellow(`\n⚠️  Finding ${findingId} not found in current results.\n`));
    return;
  }

  const reason = options.reason || "Manually suppressed";
  addSuppression(projectPath, finding, reason);

  console.log(
    chalk.green(`\n  ✅ Suppressed ${finding.id}: ${finding.title}`)
  );
  console.log(chalk.dim(`     Reason: ${reason}\n`));
}

export async function suppressRemoveCommand(
  findingId: string,
  options: { path?: string }
) {
  const projectPath = path.resolve(options.path || ".");
  const removed = removeSuppression(projectPath, findingId);

  if (removed) {
    console.log(chalk.green(`\n  ✅ Unsuppressed ${findingId}\n`));
  } else {
    console.log(chalk.yellow(`\n  ⚠️  ${findingId} was not suppressed.\n`));
  }
}

export async function suppressListCommand(options: { path?: string }) {
  const projectPath = path.resolve(options.path || ".");
  const suppressions = loadSuppressions(projectPath);

  if (suppressions.length === 0) {
    console.log(chalk.dim("\n  No suppressions.\n"));
    return;
  }

  console.log(chalk.bold(`\n  Suppressed findings (${suppressions.length}):\n`));

  for (const s of suppressions) {
    console.log(
      `  ${chalk.dim(s.id)} ${s.rule} — ${chalk.dim(s.file)}:${s.line}`
    );
    console.log(chalk.dim(`    Reason: ${s.reason} (${new Date(s.suppressedAt).toLocaleDateString()})`));
  }
  console.log();
}
