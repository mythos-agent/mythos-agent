import type Anthropic from "@anthropic-ai/sdk";

/**
 * Provider-agnostic LLM client used by the agent layer.
 *
 * The interface deliberately uses Anthropic's `messages.create` shape as
 * the canonical type — every agent in src/agent/ and src/agents/ was
 * written against that shape, and rewriting them to a third-party
 * abstraction (LangChain, Vercel AI SDK, etc.) would have a much
 * larger blast radius than the value of provider-independence in this
 * codebase.
 *
 * Adapter strategy:
 *  - `AnthropicLLMClient` (anthropic-client.ts) is a thin pass-through
 *    around the @anthropic-ai/sdk client.
 *  - `OpenAILLMClient` (openai-client.ts) translates the Anthropic-
 *    shaped request to OpenAI's `chat.completions.create`, then maps
 *    the OpenAI response back to Anthropic's `Message` shape.
 *
 * The translation surface is enumerated in issue #43; see
 * openai-client.ts inline comments for the per-field mapping. The
 * translation is one-way and lossy (some Anthropic features —
 * citations, server tool use, vision — don't map cleanly to OpenAI),
 * but covers the subset the agents actually use.
 *
 * Streaming is NOT supported in v1: callers must not pass `stream: true`.
 * The OpenAI adapter rejects it explicitly at runtime.
 */
export interface LLMClient {
  readonly messages: {
    create(params: Anthropic.MessageCreateParams): Promise<Anthropic.Message>;
  };
}
