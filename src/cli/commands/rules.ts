import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import {
  searchRulePacks,
  installRulePack,
  listInstalledPacks,
  uninstallRulePack,
  initRulePack,
} from "../../rules/registry.js";

export async function rulesSearchCommand(query: string) {
  const spinner = ora("Searching npm registry...").start();
  const packs = await searchRulePacks(query);
  spinner.stop();

  if (packs.length === 0) {
    console.log(
      chalk.yellow(`\n  No rule packs found for "${query}".\n`)
    );
    console.log(
      chalk.dim(
        "  Create your own: " + chalk.cyan("sphinx-agent rules init <name>") + "\n"
      )
    );
    return;
  }

  console.log(
    chalk.bold(`\n  Found ${packs.length} rule pack${packs.length > 1 ? "s" : ""}:\n`)
  );

  for (const pack of packs) {
    console.log(
      `  ${chalk.cyan.bold(pack.name)} ${chalk.dim(`v${pack.version}`)}` +
        (pack.author ? chalk.dim(` by ${pack.author}`) : "")
    );
    console.log(chalk.dim(`    ${pack.description}`));
    console.log(
      chalk.dim(`    Install: `) +
        chalk.cyan(`sphinx-agent rules install ${pack.name}`)
    );
    console.log();
  }
}

export async function rulesInstallCommand(name: string) {
  const projectPath = process.cwd();

  console.log(
    chalk.bold(`\n  Installing rule pack: ${chalk.cyan(name)}\n`)
  );

  const spinner = ora("Downloading and installing...").start();

  try {
    const result = await installRulePack(name, projectPath);
    spinner.succeed(
      `Installed ${result.ruleCount} rule file${result.ruleCount > 1 ? "s" : ""} to ${chalk.dim(result.rulesDir)}`
    );
    console.log(
      chalk.dim(
        "\n  Rules will be automatically loaded on next scan.\n"
      )
    );
  } catch (err) {
    spinner.fail(
      `Failed to install: ${err instanceof Error ? err.message : "unknown error"}`
    );
  }
}

export async function rulesUninstallCommand(name: string) {
  const projectPath = process.cwd();
  const removed = uninstallRulePack(name, projectPath);

  if (removed > 0) {
    console.log(
      chalk.green(
        `\n  ✅ Removed ${removed} rule file${removed > 1 ? "s" : ""} from ${name}\n`
      )
    );
  } else {
    console.log(
      chalk.yellow(`\n  ⚠️  Rule pack "${name}" not found.\n`)
    );
  }
}

export async function rulesListCommand() {
  const projectPath = process.cwd();
  const installed = listInstalledPacks(projectPath);

  if (installed.length === 0) {
    console.log(
      chalk.dim("\n  No rule packs installed.\n")
    );
    console.log(
      chalk.dim("  Search: ") +
        chalk.cyan("sphinx-agent rules search <keyword>")
    );
    console.log(
      chalk.dim("  Install: ") +
        chalk.cyan("sphinx-agent rules install <name>") +
        "\n"
    );
    return;
  }

  console.log(
    chalk.bold(`\n  Installed rule packs (${installed.length}):\n`)
  );

  for (const pack of installed) {
    console.log(`  ${chalk.cyan(pack.name)} ${chalk.dim(`(${pack.package})`)}`);
  }
  console.log();
}

export async function rulesInitCommand(name: string) {
  const outputDir = process.cwd();

  try {
    const dir = initRulePack(name, outputDir);
    console.log(
      chalk.green(`\n  ✅ Rule pack scaffolded at ${chalk.bold(dir)}\n`)
    );
    console.log(chalk.dim("  Next steps:"));
    console.log(chalk.dim(`    1. Edit ${path.join(dir, "rules.yml")} with your rules`));
    console.log(chalk.dim(`    2. cd ${dir}`));
    console.log(chalk.dim("    3. npm publish\n"));
  } catch (err) {
    console.log(
      chalk.red(
        `\n  ❌ Failed: ${err instanceof Error ? err.message : "unknown error"}\n`
      )
    );
  }
}
