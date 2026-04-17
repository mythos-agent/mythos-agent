import fs from "node:fs";
import chalk from "chalk";
import inquirer from "inquirer";
import { writeConfig } from "../../config/config.js";

export async function initCommand() {
  console.log(chalk.bold("\n🔐 sphinx-agent — Agentic AI Security Scanner\n"));
  console.log(chalk.dim("Let's set up your configuration.\n"));

  const { provider } = await inquirer.prompt({
    type: "list",
    name: "provider",
    message: "Which AI provider do you want to use?",
    choices: [
      { name: "Anthropic (Claude) — recommended", value: "anthropic" },
      { name: "OpenAI (GPT)", value: "openai" },
      { name: "Ollama (local, free)", value: "ollama" },
      { name: "LM Studio (local, free)", value: "lmstudio" },
      { name: "Other (OpenAI-compatible)", value: "custom" },
    ],
    default: "anthropic",
  });

  const isLocal = provider === "ollama" || provider === "lmstudio";

  let apiKey = "";
  if (!isLocal) {
    const providerName =
      provider === "anthropic" ? "Anthropic" : provider === "openai" ? "OpenAI" : "API";

    const result = await inquirer.prompt({
      type: "password",
      name: "apiKey",
      message: `Enter your ${providerName} API key:`,
      validate: (input: string) =>
        input.length > 0 || "API key is required for AI-powered analysis",
    });
    apiKey = result.apiKey;
  } else {
    apiKey = "not-needed";
  }

  const modelChoicesMap: Record<string, Array<{ name: string; value: string }>> = {
    anthropic: [
      { name: "Claude Sonnet 4 (fast, cost-effective)", value: "claude-sonnet-4-20250514" },
      { name: "Claude Opus 4.6 (most powerful)", value: "claude-opus-4-6-20260401" },
      { name: "Claude Haiku 4.5 (cheapest)", value: "claude-haiku-4-5-20251001" },
    ],
    openai: [
      { name: "GPT-4o (recommended)", value: "gpt-4o" },
      { name: "GPT-4o-mini (cheaper)", value: "gpt-4o-mini" },
      { name: "o1 (reasoning)", value: "o1" },
    ],
    ollama: [
      { name: "llama3.3 (general purpose)", value: "llama3.3" },
      { name: "codellama (code-focused)", value: "codellama" },
      { name: "deepseek-coder-v2 (coding)", value: "deepseek-coder-v2" },
      { name: "qwen2.5-coder (coding)", value: "qwen2.5-coder" },
    ],
    lmstudio: [{ name: "Enter model name manually", value: "_custom" }],
    custom: [{ name: "Enter model name manually", value: "_custom" }],
  };

  const choices = modelChoicesMap[provider] || modelChoicesMap.custom;
  let model: string;

  const { modelChoice } = await inquirer.prompt({
    type: "list",
    name: "modelChoice",
    message: "Which model do you want to use?",
    choices,
  });

  if (modelChoice === "_custom") {
    const { customModel } = await inquirer.prompt({
      type: "input",
      name: "customModel",
      message: "Enter the model name:",
      validate: (input: string) => input.length > 0 || "Model name required",
    });
    model = customModel;
  } else {
    model = modelChoice;
  }

  const configPath = writeConfig(".", {
    provider,
    apiKey,
    model,
  });

  // Auto-add .sphinx.yml to .gitignore
  if (!isLocal) {
    const gitignorePath = ".gitignore";
    let gitignore = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, "utf-8") : "";
    if (!gitignore.includes(".sphinx.yml")) {
      gitignore += `${gitignore.endsWith("\n") ? "" : "\n"}.sphinx.yml\n`;
      fs.writeFileSync(gitignorePath, gitignore);
    }
  }

  console.log(chalk.green(`\n✅ Configuration saved to ${configPath}`));
  if (!isLocal) {
    console.log(chalk.dim("   .sphinx.yml added to .gitignore automatically."));
  }

  const costNote = isLocal ? chalk.green("   Using local model — no API costs!") : "";
  if (costNote) console.log(costNote);

  console.log(
    chalk.bold("\n  Run ") +
      chalk.cyan("sphinx-agent scan") +
      chalk.bold(" to scan your project.\n")
  );
}
