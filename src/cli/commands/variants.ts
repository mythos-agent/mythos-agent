import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";
import {
  VariantAnalyzer,
  variantsToVulnerabilities,
} from "../../analysis/variant-analyzer.js";

interface VariantsOptions {
  path?: string;
  auto?: boolean;
  json?: boolean;
}

const SIMILARITY_COLORS: Record<string, (s: string) => string> = {
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
};

export async function variantsCommand(
  cveId: string | undefined,
  options: VariantsOptions
) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);

  if (!config.apiKey) {
    console.log(
      chalk.yellow(
        "\n⚠️  API key required for variant analysis. Run " +
          chalk.cyan("sphinx-agent init") +
          " to configure.\n"
      )
    );
    return;
  }

  console.log(
    chalk.bold("\n🔬 sphinx-agent variants — CVE Variant Analysis\n")
  );
  console.log(chalk.dim(`Project: ${projectPath}\n`));

  const analyzer = new VariantAnalyzer(config, projectPath);

  if (options.auto || !cveId) {
    // Auto mode: scan for common vulnerability variants
    const spinner = ora(
      "Running automatic variant analysis..."
    ).start();

    const results = await analyzer.autoScan();
    spinner.stop();

    if (results.length === 0) {
      console.log(chalk.green("  ✅ No vulnerability variants detected.\n"));
      return;
    }

    for (const { cve, variants } of results) {
      console.log(
        chalk.bold(`\n  ${cve.id}: `) + chalk.dim(cve.description.slice(0, 80))
      );

      for (const v of variants) {
        const color = SIMILARITY_COLORS[v.similarity] || chalk.dim;
        console.log(
          `\n    ${color(`[${v.similarity.toUpperCase()}]`)} ${chalk.bold(v.id)}`
        );
        console.log(
          chalk.dim(`    ${v.file}:${v.line}`)
        );
        console.log(`    ${v.explanation}`);
        if (v.code) {
          console.log(chalk.dim(`    > ${v.code.slice(0, 100)}`));
        }
      }
    }
    console.log();
    return;
  }

  // Specific CVE mode
  const spinner = ora(`Fetching ${cveId} and searching for variants...`).start();

  const cveInfo = await analyzer.fetchCveInfo(cveId);
  if (!cveInfo) {
    spinner.fail(`Could not fetch CVE details for ${cveId}`);
    return;
  }

  spinner.text = `Found ${cveId}: searching codebase for variants...`;
  const variants = await analyzer.findVariants(cveId);
  spinner.stop();

  console.log(
    chalk.bold(`  ${cveInfo.id}`) +
      chalk.dim(` [${cveInfo.severity.toUpperCase()}]`)
  );
  console.log(chalk.dim(`  ${cveInfo.description.slice(0, 120)}\n`));

  if (variants.length === 0) {
    console.log(
      chalk.green(`  ✅ No variants of ${cveId} found in this codebase.\n`)
    );
    return;
  }

  console.log(
    chalk.red.bold(`  Found ${variants.length} variant(s):\n`)
  );

  for (const v of variants) {
    const color = SIMILARITY_COLORS[v.similarity] || chalk.dim;
    console.log(
      `  ${color(`[${v.similarity.toUpperCase()}]`)} ${chalk.bold(v.id)} — ${v.rootCauseMatch}`
    );
    console.log(chalk.dim(`    ${v.file}:${v.line}`));
    console.log(`    ${v.explanation}`);
    if (v.code) {
      console.log(chalk.dim(`    > ${v.code.slice(0, 120)}`));
    }
    console.log();
  }

  if (options.json) {
    console.log(JSON.stringify({ cve: cveInfo, variants }, null, 2));
  }
}
