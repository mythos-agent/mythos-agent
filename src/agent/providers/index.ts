import type { AIProvider } from "./base.js";
import { AnthropicProvider } from "./anthropic.js";
import { OpenAICompatibleProvider } from "./openai-compatible.js";
import type { SphinxConfig } from "../../types/index.js";

export type { AIProvider, UsageTracker } from "./base.js";
export { createUsageTracker, trackUsage } from "./base.js";

export function createProvider(config: SphinxConfig): AIProvider {
  const apiKey = config.apiKey;
  if (!apiKey) {
    throw new Error("API key required. Run 'shedu init' to configure.");
  }

  switch (config.provider) {
    case "anthropic":
      return new AnthropicProvider(apiKey, config.model);

    case "openai":
      return new OpenAICompatibleProvider({
        name: "openai",
        apiKey,
        model: config.model,
        baseUrl: "https://api.openai.com/v1",
        inputCostPer1M: getOpenAICost(config.model).input,
        outputCostPer1M: getOpenAICost(config.model).output,
      });

    default:
      // Treat unknown providers as OpenAI-compatible (Ollama, vLLM, etc.)
      return new OpenAICompatibleProvider({
        name: config.provider,
        apiKey,
        model: config.model,
        baseUrl: getBaseUrl(config.provider),
        inputCostPer1M: 0,
        outputCostPer1M: 0,
      });
  }
}

function getOpenAICost(model: string): { input: number; output: number } {
  if (model.includes("gpt-4o-mini")) return { input: 0.15, output: 0.6 };
  if (model.includes("gpt-4o")) return { input: 2.5, output: 10 };
  if (model.includes("gpt-4")) return { input: 30, output: 60 };
  if (model.includes("o1")) return { input: 15, output: 60 };
  return { input: 2.5, output: 10 };
}

function getBaseUrl(provider: string): string {
  switch (provider) {
    case "ollama":
      return "http://localhost:11434/v1";
    case "lmstudio":
      return "http://localhost:1234/v1";
    case "vllm":
      return "http://localhost:8000/v1";
    default:
      return "http://localhost:8080/v1";
  }
}
