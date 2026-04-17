import path from "node:path";
import chalk from "chalk";
import ora from "ora";
import inquirer from "inquirer";
import { loadConfig } from "../../config/config.js";
import { QueryEngine } from "../../agent/query-engine.js";

export async function askCommand(
  question: string | undefined,
  options: { path?: string; interactive?: boolean }
) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);

  if (!config.apiKey) {
    console.log(
      chalk.yellow(
        "\n⚠️  API key required for sphinx-agent ask. Run " +
          chalk.cyan("sphinx-agent init") +
          " to configure.\n"
      )
    );
    return;
  }

  console.log(chalk.bold("\n🔐 sphinx-agent ask — AI Security Analysis\n"));
  console.log(chalk.dim(`Project: ${projectPath}\n`));

  const engine = new QueryEngine(config, projectPath);

  if (question && !options.interactive) {
    // Single question mode
    await executeQuery(engine, question);
    return;
  }

  // Interactive mode
  console.log(
    chalk.dim(
      "Ask security questions about your codebase. Type " + chalk.cyan("exit") + " to quit.\n"
    )
  );
  console.log(chalk.dim("Examples:"));
  console.log(chalk.dim('  "Show me all unvalidated user inputs"'));
  console.log(chalk.dim('  "Are there any SQL injection risks?"'));
  console.log(chalk.dim('  "Check the authentication flow for bypasses"'));
  console.log(chalk.dim('  "Find hardcoded secrets"'));
  console.log(chalk.dim('  "Is the session management secure?"'));
  console.log();

  while (true) {
    const { userQuestion } = await inquirer.prompt({
      type: "input",
      name: "userQuestion",
      message: chalk.cyan("sphinx-agent>"),
      validate: (input: string) => input.trim().length > 0 || "Please enter a question",
    });

    const trimmed = userQuestion.trim();
    if (
      trimmed.toLowerCase() === "exit" ||
      trimmed.toLowerCase() === "quit" ||
      trimmed.toLowerCase() === "q"
    ) {
      console.log(chalk.dim("\nGoodbye!\n"));
      break;
    }

    if (trimmed.toLowerCase() === "clear") {
      engine.clearHistory();
      console.log(chalk.dim("Conversation history cleared.\n"));
      continue;
    }

    await executeQuery(engine, trimmed);
  }
}

async function executeQuery(engine: QueryEngine, question: string) {
  const spinner = ora("Analyzing codebase...").start();

  try {
    const answer = await engine.query(question);
    spinner.stop();

    console.log(chalk.dim("─".repeat(50)));
    console.log();
    console.log(answer);
    console.log();
    console.log(chalk.dim("─".repeat(50)));
    console.log();
  } catch (err) {
    spinner.fail(`Error: ${err instanceof Error ? err.message : "unknown error"}`);
  }
}
