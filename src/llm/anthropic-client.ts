import Anthropic from "@anthropic-ai/sdk";
import type { LLMClient } from "./llm-client.js";

const EPHEMERAL = { type: "ephemeral" as const };

/**
 * Apply prompt-cache breakpoints to the stable prefix of a request:
 * the system prompt and the tool definitions. The growing `messages`
 * transcript is left uncached. Anthropic caches everything from the
 * start of the prompt up to and including a `cache_control` marker, so
 * one marker on the system block covers tools + system; the marker on
 * the last tool is a defensive second breakpoint for tool-only requests.
 *
 * Note: the cache only engages above the model's minimum cacheable
 * prompt length; short prompts simply go uncached (no error).
 */
export function withPromptCache(
  params: Anthropic.MessageCreateParams
): Anthropic.MessageCreateParams {
  const next: Anthropic.MessageCreateParams = { ...params };

  if (typeof next.system === "string" && next.system.length > 0) {
    next.system = [{ type: "text", text: next.system, cache_control: EPHEMERAL }];
  } else if (Array.isArray(next.system) && next.system.length > 0) {
    const blocks = next.system.map((b) => ({ ...b }));
    blocks[blocks.length - 1] = { ...blocks[blocks.length - 1], cache_control: EPHEMERAL };
    next.system = blocks;
  }

  if (Array.isArray(next.tools) && next.tools.length > 0) {
    const tools = next.tools.map((t) => ({ ...t }));
    tools[tools.length - 1] = { ...tools[tools.length - 1], cache_control: EPHEMERAL };
    next.tools = tools as Anthropic.MessageCreateParams["tools"];
  }

  return next;
}

/**
 * Tier-1 provider client. Thin wrapper around @anthropic-ai/sdk that
 * applies prompt caching to every request's stable prefix.
 *
 * The narrowing on `messages.create` (only non-streaming, returning
 * Message rather than Message | MessageStream) matches LLMClient's
 * narrower contract. Anthropic SDK's actual signature is overloaded
 * to include streaming; the cast here is sound for the agent
 * layer's use because no agent passes `stream: true`.
 */
export class AnthropicLLMClient implements LLMClient {
  private readonly inner: Anthropic;

  constructor(opts: { apiKey?: string; baseURL?: string }) {
    this.inner = new Anthropic({ apiKey: opts.apiKey, baseURL: opts.baseURL });
  }

  readonly messages = {
    create: (params: Anthropic.MessageCreateParams): Promise<Anthropic.Message> =>
      this.inner.messages.create(withPromptCache(params)) as Promise<Anthropic.Message>,
  };
}
