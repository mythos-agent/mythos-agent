import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";
import { TaintTracker, type TaintFlow } from "../../agent/taint-tracker.js";

interface TaintOptions {
  json?: boolean;
}

const SEVERITY_COLORS: Record<string, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
};

export async function taintCommand(taintPath: string, options: TaintOptions) {
  const projectPath = path.resolve(taintPath);
  const config = loadConfig(projectPath);

  if (!config.apiKey) {
    console.log(
      chalk.yellow(
        "\n⚠️  API key required for taint analysis. Run " +
          chalk.cyan("sphinx-agent init") +
          " to configure.\n"
      )
    );
    return;
  }

  console.log(
    chalk.bold("\n🔬 sphinx-agent taint — AI Data Flow Analysis\n")
  );
  console.log(chalk.dim(`Project: ${projectPath}\n`));

  const spinner = ora(
    "Tracing data flows from sources to sinks..."
  ).start();

  const tracker = new TaintTracker(config);

  try {
    const flows = await tracker.analyze(projectPath);
    spinner.stop();

    if (flows.length === 0) {
      console.log(
        chalk.green("  ✅ No unsafe data flows detected.\n")
      );
      return;
    }

    if (options.json) {
      console.log(JSON.stringify({ flows }, null, 2));
      return;
    }

    console.log(
      chalk.bold.red(
        `  Found ${flows.length} tainted data flow${flows.length > 1 ? "s" : ""}:\n`
      )
    );

    for (const flow of flows) {
      renderFlow(flow);
    }
  } catch (err) {
    spinner.fail(
      `Taint analysis failed: ${err instanceof Error ? err.message : "unknown error"}`
    );
  }
}

function renderFlow(flow: TaintFlow): void {
  const color = SEVERITY_COLORS[flow.severity] || chalk.dim;

  console.log(
    `  ${color(` ${flow.severity.toUpperCase()} `)} ${chalk.bold(flow.id)}`
  );
  console.log();

  // Source
  console.log(
    chalk.green("  ▶ SOURCE: ") + flow.source.description
  );
  console.log(
    chalk.dim(`    ${flow.source.file}:${flow.source.line}`)
  );
  console.log(chalk.dim(`    > ${flow.source.snippet}`));
  console.log();

  // Intermediate steps
  for (const step of flow.intermediateSteps) {
    console.log(
      chalk.yellow("  ↓ ") + chalk.dim(step.description)
    );
    console.log(
      chalk.dim(`    ${step.file}:${step.line}`)
    );
    console.log(chalk.dim(`    > ${step.snippet}`));
    console.log();
  }

  // Sink
  console.log(
    chalk.red("  ◆ SINK: ") + flow.sink.description
  );
  console.log(
    chalk.dim(`    ${flow.sink.file}:${flow.sink.line}`)
  );
  console.log(chalk.dim(`    > ${flow.sink.snippet}`));
  console.log();

  // Narrative
  console.log(chalk.dim("  → ") + chalk.italic(flow.narrative));
  console.log();
  console.log(chalk.dim("  " + "─".repeat(46)));
  console.log();
}
