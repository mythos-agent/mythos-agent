import type { MythosConfig } from "../types/index.js";
import type { LLMClient } from "./llm-client.js";
import { AnthropicLLMClient } from "./anthropic-client.js";
import { OpenAILLMClient } from "./openai-client.js";
import {
  ORCAROUTER_DEFAULT_MODEL,
  isOrcaRouterProvider,
  resolveOrcaRouterBaseUrl,
} from "./orcarouter.js";

export type { LLMClient } from "./llm-client.js";
export { AnthropicLLMClient } from "./anthropic-client.js";
export { OpenAILLMClient } from "./openai-client.js";
export * from "./orcarouter.js";
export * from "./orcarouter-models.js";

/**
 * Factory: returns the right LLMClient for the given config's
 * `provider` field. Defaults to Tier 1 (Anthropic) so any caller that
 * doesn't set `provider` gets byte-identical behavior to the
 * pre-multi-model code path.
 *
 * `provider: "anthropic"` (default) → AnthropicLLMClient (Tier 1).
 *
 * `provider: "orcarouter"` → OpenAILLMClient pinned to the OrcaRouter
 * Cyber Inference base URL (`https://api.orcarouter.ai/v1`) unless the
 * user explicitly overrides `baseURL` (self-hosted deployment). The
 * OrcaRouter model is forwarded verbatim so the vendor/model namespace
 * survives the round trip.
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
  if (isOrcaRouterProvider(config.provider)) {
    return new OpenAILLMClient({
      apiKey: config.apiKey,
      baseURL: resolveOrcaRouterBaseUrl(config),
    });
  }
  return new OpenAILLMClient({
    apiKey: config.apiKey,
    baseURL: config.baseURL,
  });
}

/**
 * Model to send upstream for a config. OrcaRouter is a named provider with
 * a working default: an unset or Anthropic-shaped model id (the config
 * default) is replaced by `orcarouter/auto` so a user who merely flips
 * `provider: orcarouter` gets a routable request.
 */
export function resolveModelForProvider(config: MythosConfig): string {
  const model = (config.model ?? "").trim();
  if (!isOrcaRouterProvider(config.provider)) return model;
  if (!model || model.startsWith("claude-")) return ORCAROUTER_DEFAULT_MODEL;
  return model;
}
