import fs from "node:fs";
import chalk from "chalk";
import inquirer from "inquirer";
import { CANONICAL_CONFIG_FILENAME, writeConfig } from "../../config/config.js";
import {
  ORCAROUTER_API_BASE_URL,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_KEY_DASHBOARD_URL,
  ORCAROUTER_PROVIDER_ID,
  ORCAROUTER_PROVIDER_LABEL,
  looksLikeOrcaRouterKey,
} from "../../llm/orcarouter.js";
import { discoverOrcaRouterModels } from "../../llm/orcarouter-models.js";

export async function initCommand() {
  console.log(chalk.bold("\n🔐 mythos-agent — Agentic AI Security Scanner\n"));
  console.log(chalk.dim("Let's set up your configuration.\n"));

  const { provider } = await inquirer.prompt({
    type: "list",
    name: "provider",
    message: "Which AI provider do you want to use?",
    choices: [...INIT_PROVIDER_CHOICES],
    default: "anthropic",
  });

  const isLocal = provider === "ollama" || provider === "lmstudio";
  const isOrcaRouter = provider === ORCAROUTER_PROVIDER_ID;

  let apiKey = "";
  if (!isLocal) {
    const providerName =
      provider === "anthropic"
        ? "Anthropic"
        : provider === "openai"
          ? "OpenAI"
          : isOrcaRouter
            ? ORCAROUTER_PROVIDER_LABEL
            : "API";

    if (isOrcaRouter) {
      console.log(
        chalk.dim(`   Create or copy a key at ${ORCAROUTER_KEY_DASHBOARD_URL}`) +
          chalk.dim(` (sk-orca-…). Inference: ${ORCAROUTER_API_BASE_URL}`)
      );
    }

    const result = await inquirer.prompt({
      type: "password",
      name: "apiKey",
      message: `Enter your ${providerName} API key:`,
      validate: (input: string) => {
        if (input.length === 0) return "API key is required for AI-powered analysis";
        if (isOrcaRouter && !looksLikeOrcaRouterKey(input.trim())) {
          // Format hint only — an `sk-orca-` prefix is not proof the key is
          // valid. The first real request establishes validity.
          return "OrcaRouter keys start with sk-orca- (check for a truncated paste)";
        }
        return true;
      },
    });
    apiKey = result.apiKey.trim();
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

  let model: string;

  if (isOrcaRouter) {
    model = await pickOrcaRouterModel(apiKey);
  } else {
    const choices = modelChoicesMap[provider] || modelChoicesMap.custom;

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
    for (const secretFile of [".sphinx.yml", CANONICAL_CONFIG_FILENAME]) {
      if (!gitignore.includes(secretFile)) {
        gitignore += `${gitignore.endsWith("\n") ? "" : "\n"}${secretFile}\n`;
      }
    }
    fs.writeFileSync(gitignorePath, gitignore);
  }

  console.log(chalk.green(`\n✅ Configuration saved to ${configPath}`));
  if (!isLocal) {
    console.log(
      chalk.dim(
        `   ${CANONICAL_CONFIG_FILENAME} (holds your key) added to .gitignore automatically.`
      )
    );
  }

  const costNote = isLocal ? chalk.green("   Using local model — no API costs!") : "";
  if (costNote) console.log(costNote);

  console.log(
    chalk.bold("\n  Run ") +
      chalk.cyan("mythos-agent scan") +
      chalk.bold(" to scan your project.\n")
  );
}

/**
 * Provider choices offered by `mythos-agent init`. Exported so tests can
 * assert OrcaRouter is registered as a named, selectable provider.
 */
export const INIT_PROVIDER_CHOICES: ReadonlyArray<{ name: string; value: string }> = [
  { name: "Anthropic (Claude) — recommended", value: "anthropic" },
  { name: "OpenAI (GPT)", value: "openai" },
  { name: "Ollama (local, free)", value: "ollama" },
  { name: "LM Studio (local, free)", value: "lmstudio" },
  { name: `${ORCAROUTER_PROVIDER_LABEL} (cyber-tier gateway)`, value: ORCAROUTER_PROVIDER_ID },
  { name: "Other (OpenAI-compatible)", value: "custom" },
];

/**
 * OrcaRouter model picker. The list comes from the live
 * `GET https://api.orcarouter.ai/v1/models` catalog for the user's key; it
 * is never a hand-written sample. If discovery fails (offline, revoked key,
 * catalog outage) the verified seed is offered with an explicit
 * "degraded" warning instead of falling back to free-text entry.
 */
async function pickOrcaRouterModel(apiKey: string): Promise<string> {
  const discovery = await discoverOrcaRouterModels({ apiKey });
  if (discovery.degraded) {
    console.log(
      chalk.yellow("⚠️  Could not load the OrcaRouter model catalog") +
        chalk.dim(` (${discovery.error ?? discovery.status}).`)
    );
    console.log(chalk.yellow(`   Showing the verified fallback list; rerun later to refresh it.`));
  } else {
    console.log(
      chalk.dim(
        `   Loaded ${discovery.models.length} chat models from ${ORCAROUTER_API_BASE_URL}/models`
      )
    );
  }

  const { modelChoice } = await inquirer.prompt({
    type: "list",
    name: "modelChoice",
    message: "Which OrcaRouter model do you want to use?",
    choices: discovery.models.map((m) => ({
      name:
        m.id === ORCAROUTER_DEFAULT_MODEL
          ? `${m.name} — default`
          : m.source === "seed"
            ? `${m.name} [offline seed]`
            : m.name,
      value: m.id,
    })),
    default: ORCAROUTER_DEFAULT_MODEL,
  });

  const chosen = typeof modelChoice === "string" ? modelChoice : "";
  return chosen || ORCAROUTER_DEFAULT_MODEL;
}
