import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";
import { loadResults } from "../../store/results-store.js";
import { AIFixer, applyPatch, type Patch } from "../../agent/fixer.js";
import type { Severity, Vulnerability } from "../../types/index.js";

interface FixOptions {
  apply?: boolean;
  dryRun?: boolean;
  id?: string[];
  severity: Severity;
}

export async function fixCommand(fixPath: string, options: FixOptions) {
  const projectPath = path.resolve(fixPath);
  const config = loadConfig(projectPath);
  const result = loadResults(projectPath);

  if (!result) {
    console.log(
      chalk.yellow(
        "\n⚠️  No scan results found. Run " +
          chalk.cyan("sphinx-agent scan") +
          " first.\n"
      )
    );
    return;
  }

  if (!config.apiKey) {
    console.log(
      chalk.yellow(
        "\n⚠️  API key required for fix generation. Run " +
          chalk.cyan("sphinx-agent init") +
          " to configure.\n"
      )
    );
    return;
  }

  // Filter vulnerabilities
  let vulns = result.confirmedVulnerabilities;

  if (options.id && options.id.length > 0) {
    const ids = new Set(options.id.map((id) => id.toUpperCase()));
    vulns = vulns.filter((v) => ids.has(v.id));
  }

  const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  const thresholdIdx = severityOrder.indexOf(options.severity);
  vulns = vulns.filter(
    (v) => severityOrder.indexOf(v.severity) <= thresholdIdx
  );

  if (vulns.length === 0) {
    console.log(chalk.green("\n✅ No vulnerabilities to fix.\n"));
    return;
  }

  console.log(
    chalk.bold("\n🔧 sphinx-agent fix — AI-Powered Patch Generation")
  );
  console.log(chalk.dim("━".repeat(50)));
  console.log(
    chalk.dim(
      `\nGenerating patches for ${vulns.length} vulnerabilit${vulns.length > 1 ? "ies" : "y"}...\n`
    )
  );

  const spinner = ora("Generating patches with AI").start();

  const fixer = new AIFixer(config);
  const patches = await fixer.generatePatches(vulns, projectPath);

  if (patches.length === 0) {
    spinner.warn("No patches could be generated");
    return;
  }

  spinner.succeed(`Generated ${patches.length} patch${patches.length > 1 ? "es" : ""}`);
  console.log();

  // Display patches
  for (const patch of patches) {
    renderPatch(patch);
  }

  // Apply if requested
  if (options.apply) {
    console.log(chalk.bold("\n📝 Applying patches...\n"));

    let applied = 0;
    let failed = 0;

    for (const patch of patches) {
      const success = applyPatch(projectPath, patch);
      if (success) {
        console.log(
          chalk.green(`  ✅ ${patch.vulnerabilityId}`) +
            chalk.dim(` — ${patch.file}`)
        );
        applied++;
      } else {
        console.log(
          chalk.red(`  ❌ ${patch.vulnerabilityId}`) +
            chalk.dim(` — could not apply patch to ${patch.file}`)
        );
        failed++;
      }
    }

    console.log(
      chalk.bold(
        `\n  ${chalk.green(`${applied} applied`)}${failed > 0 ? `, ${chalk.red(`${failed} failed`)}` : ""}\n`
      )
    );

    if (applied > 0) {
      console.log(
        chalk.dim(
          "  Run " +
            chalk.cyan("sphinx-agent scan") +
            " again to verify fixes.\n"
        )
      );
    }
  } else {
    console.log(
      chalk.dim(
        "\n  This was a dry run. To apply patches, run:\n  " +
          chalk.cyan("sphinx-agent fix --apply") +
          "\n"
      )
    );
  }
}

function renderPatch(patch: Patch): void {
  console.log(
    chalk.bold(`  ${patch.vulnerabilityId}`) +
      chalk.dim(` — ${patch.file}`)
  );
  console.log(chalk.dim(`  ${patch.description}`));
  console.log();

  // Show diff
  const originalLines = patch.original.split("\n");
  const fixedLines = patch.fixed.split("\n");

  for (const line of originalLines) {
    console.log(chalk.red(`  - ${line}`));
  }
  for (const line of fixedLines) {
    console.log(chalk.green(`  + ${line}`));
  }
  console.log();
}
