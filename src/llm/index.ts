import type { MythosConfig } from "../types/index.js";
import type { LLMClient } from "./llm-client.js";
import { AnthropicLLMClient } from "./anthropic-client.js";
import { OpenAILLMClient } from "./openai-client.js";

export type { LLMClient } from "./llm-client.js";
export { AnthropicLLMClient } from "./anthropic-client.js";
export { OpenAILLMClient } from "./openai-client.js";

/**
 * Factory: returns the right LLMClient for the given config's
 * `provider` field. Defaults to Tier 1 (Anthropic) so any caller that
 * doesn't set `provider` gets byte-identical behavior to the
 * pre-multi-model code path.
 *
 * `provider: "anthropic"` (default) → AnthropicLLMClient (Tier 1).
 *
 * Anything else (`"openai"`, `"qwen"`, `"ollama"`, `"lmstudio"`,
 * `"vllm"`, custom string) → OpenAILLMClient (Tier 2). The OpenAI
 * adapter speaks the OpenAI-compatible HTTP shape that virtually
 * every modern provider exposes; per the tier policy in
 * docs/multi-model.md, that single adapter covers ~95% of real
 * demand without needing per-provider SDKs.
 */
export function createLLMClient(config: MythosConfig): LLMClient {
  if (!config.provider || config.provider === "anthropic") {
    return new AnthropicLLMClient({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    });
  }
  return new OpenAILLMClient({
    apiKey: config.apiKey,
    baseURL: config.baseURL,
  });
}
