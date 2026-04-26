import Anthropic from "@anthropic-ai/sdk";
import type { LLMClient } from "./llm-client.js";

/**
 * Tier-1 provider client. Thin pass-through around @anthropic-ai/sdk —
 * the canonical implementation of LLMClient. New scanner work and
 * benchmark catch-rate measurements both target this client.
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
      this.inner.messages.create(params) as Promise<Anthropic.Message>,
  };
}
