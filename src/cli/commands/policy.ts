import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import {
  loadPolicy,
  evaluatePolicy,
  generateDefaultPolicy,
  getComplianceMapping,
  type PolicyResult,
} from "../../policy/engine.js";
import { loadResults } from "../../store/results-store.js";

export async function policyCheckCommand(options: { path?: string; json?: boolean }) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(
      chalk.yellow("\n⚠️  No scan results. Run " + chalk.cyan("sphinx-agent scan") + " first.\n")
    );
    return;
  }

  const policy = loadPolicy(projectPath);
  if (!policy) {
    console.log(
      chalk.yellow(
        "\n⚠️  No policy found. Run " + chalk.cyan("sphinx-agent policy init") + " to create one.\n"
      )
    );
    return;
  }

  const policyResult = evaluatePolicy(policy, result);

  if (options.json) {
    console.log(JSON.stringify(policyResult, null, 2));
    return;
  }

  renderPolicyResult(policy.name, policyResult);

  if (!policyResult.passed) {
    process.exit(1);
  }
}

export async function policyInitCommand(options: { path?: string }) {
  const projectPath = path.resolve(options.path || ".");
  const policyDir = path.join(projectPath, ".sphinx");
  const policyPath = path.join(policyDir, "policy.yml");

  if (fs.existsSync(policyPath)) {
    console.log(chalk.yellow(`\n⚠️  Policy already exists at ${policyPath}\n`));
    return;
  }

  if (!fs.existsSync(policyDir)) {
    fs.mkdirSync(policyDir, { recursive: true });
  }

  fs.writeFileSync(policyPath, generateDefaultPolicy(), "utf-8");
  console.log(chalk.green(`\n✅ Policy created at ${policyPath}\n`));
  console.log(chalk.dim("  Edit the policy, then run:"));
  console.log(chalk.cyan("  sphinx-agent policy check\n"));
}

function renderPolicyResult(policyName: string, result: PolicyResult): void {
  console.log(chalk.bold(`\n📋 sphinx-agent policy — ${policyName}\n`));
  console.log(chalk.dim("━".repeat(50)));

  if (result.passed && result.warnings.length === 0) {
    console.log(chalk.green.bold("\n  ✅ All policy checks passed.\n"));
    return;
  }

  // Violations (blocks)
  if (result.violations.length > 0) {
    console.log(
      chalk.red.bold(
        `\n  ❌ ${result.violations.length} policy violation${result.violations.length > 1 ? "s" : ""} (blocking):\n`
      )
    );

    for (const v of result.violations) {
      console.log(chalk.red(`  BLOCK `) + chalk.bold(v.ruleId) + chalk.dim(` — ${v.description}`));
      console.log(
        chalk.dim(
          `    Matched ${v.matchedFindings.length} finding${v.matchedFindings.length > 1 ? "s" : ""}`
        )
      );
      if (v.compliance && v.compliance.length > 0) {
        console.log(chalk.dim("    Compliance: ") + v.compliance.join(", "));
      }
      console.log();
    }
  }

  // Warnings
  if (result.warnings.length > 0) {
    console.log(
      chalk.yellow(
        `  ⚠️  ${result.warnings.length} warning${result.warnings.length > 1 ? "s" : ""}:\n`
      )
    );

    for (const w of result.warnings) {
      console.log(
        chalk.yellow(`  WARN `) + chalk.bold(w.ruleId) + chalk.dim(` — ${w.description}`)
      );
      console.log(
        chalk.dim(
          `    Matched ${w.matchedFindings.length} finding${w.matchedFindings.length > 1 ? "s" : ""}`
        )
      );
      console.log();
    }
  }

  // Summary
  if (!result.passed) {
    console.log(chalk.red.bold("  Policy check FAILED — merge should be blocked.\n"));
  } else {
    console.log(chalk.yellow("  Policy check passed with warnings.\n"));
  }
}
