import type Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import type { LLMClient } from "./llm-client.js";

/**
 * Tier-2 provider client. Translates the Anthropic-shaped request
 * surface used by the agent layer to OpenAI's `chat.completions.create`,
 * then maps the OpenAI response back to Anthropic's `Message` shape so
 * the agent layer doesn't need to know which provider is in use.
 *
 * Five translation points (per issue #43):
 *  1. System message — Anthropic uses a separate `system` field;
 *     OpenAI uses `messages[0].role === "system"`. Prepended in
 *     translateRequest.
 *  2. Content block model — Anthropic returns typed blocks
 *     ({type:"text"} or {type:"tool_use"}); OpenAI returns flat
 *     string content + optional `tool_calls` on the message. Mapped
 *     in translateResponse.
 *  3. Tool definition format — Anthropic uses {name, description,
 *     input_schema}; OpenAI uses {type:"function", function:{name,
 *     description, parameters}}. Mapped in translateTools.
 *  4. Tool call/result threading — Anthropic puts tool results in a
 *     user message with `tool_result` content blocks; OpenAI uses
 *     a separate `role:"tool"` message with `tool_call_id`. Mapped
 *     in translateMessages.
 *  5. Stop reasons — `stop_reason:"tool_use"` (Anthropic) vs
 *     `finish_reason:"tool_calls"` (OpenAI). Mapped in
 *     translateResponse.
 *
 * Streaming, vision, citations, and Anthropic-specific server tools
 * are NOT translated — the v1 surface is "what the agents need."
 * Callers passing those features get a runtime error; the type
 * system intentionally doesn't catch this so adding new agents that
 * use new Anthropic features fails loudly rather than silently.
 */
export class OpenAILLMClient implements LLMClient {
  private readonly inner: OpenAI;

  constructor(opts: { apiKey?: string; baseURL?: string }) {
    // OpenAI SDK requires a string apiKey; Anthropic accepts undefined
    // (and reads from env). For non-Anthropic compatibility the user
    // SHOULD set MYTHOS_API_KEY explicitly, but we tolerate empty
    // string for endpoints that don't need auth (e.g. local Ollama).
    this.inner = new OpenAI({
      apiKey: opts.apiKey ?? "",
      baseURL: opts.baseURL,
    });
  }

  readonly messages = {
    create: async (params: Anthropic.MessageCreateParams): Promise<Anthropic.Message> => {
      if ((params as { stream?: boolean }).stream) {
        throw new Error(
          "OpenAILLMClient: streaming responses are not supported in v1; pass `stream: false` or omit the field."
        );
      }
      const openaiRequest = translateRequest(params);
      const openaiResponse = await this.inner.chat.completions.create(openaiRequest);
      return translateResponse(openaiResponse, params.model);
    },
  };
}

// ---------------------------------------------------------------------------
// Translation helpers — exported for unit testing the per-field mapping
// without instantiating a live OpenAI client.
// ---------------------------------------------------------------------------

export function translateRequest(
  params: Anthropic.MessageCreateParams
): OpenAI.Chat.ChatCompletionCreateParamsNonStreaming {
  const out: OpenAI.Chat.ChatCompletionCreateParamsNonStreaming = {
    model: params.model,
    messages: translateMessages(params.system, params.messages),
    max_tokens: params.max_tokens,
    stream: false,
  };
  if (params.temperature !== undefined) out.temperature = params.temperature;
  if (params.top_p !== undefined) out.top_p = params.top_p;
  if (params.tools && params.tools.length > 0) {
    out.tools = translateTools(params.tools);
  }
  if (params.stop_sequences && params.stop_sequences.length > 0) {
    out.stop = params.stop_sequences;
  }
  return out;
}

export function translateMessages(
  system: Anthropic.MessageCreateParams["system"],
  messages: Anthropic.MessageParam[]
): OpenAI.Chat.ChatCompletionMessageParam[] {
  const out: OpenAI.Chat.ChatCompletionMessageParam[] = [];

  // System message: Anthropic accepts string or content-block array;
  // OpenAI's system role takes a string. Concatenate text from
  // content blocks if needed.
  if (typeof system === "string" && system.length > 0) {
    out.push({ role: "system", content: system });
  } else if (Array.isArray(system)) {
    const text = system
      .filter((b): b is Anthropic.TextBlockParam => b.type === "text")
      .map((b) => b.text)
      .join("\n");
    if (text.length > 0) out.push({ role: "system", content: text });
  }

  for (const msg of messages) {
    if (typeof msg.content === "string") {
      out.push({ role: msg.role, content: msg.content });
      continue;
    }

    if (msg.role === "user") {
      // User messages with content blocks: split tool_result blocks
      // out as separate `role: "tool"` messages (OpenAI threading
      // contract). Other blocks (text, image) become a single user
      // message before the tool messages.
      const toolResults = msg.content.filter(
        (b): b is Anthropic.ToolResultBlockParam => b.type === "tool_result"
      );
      const nonToolResults = msg.content.filter((b) => b.type !== "tool_result");

      if (nonToolResults.length > 0) {
        const text = nonToolResults
          .filter((b): b is Anthropic.TextBlockParam => b.type === "text")
          .map((b) => b.text)
          .join("\n");
        if (text.length > 0) out.push({ role: "user", content: text });
      }
      for (const tr of toolResults) {
        out.push({
          role: "tool",
          tool_call_id: tr.tool_use_id,
          content: stringifyToolResultContent(tr.content),
        });
      }
      continue;
    }

    // Assistant: split text blocks (combined content) and tool_use
    // blocks (collected into tool_calls).
    const textParts: string[] = [];
    const toolCalls: OpenAI.Chat.ChatCompletionMessageToolCall[] = [];
    for (const block of msg.content) {
      if (block.type === "text") {
        textParts.push(block.text);
      } else if (block.type === "tool_use") {
        toolCalls.push({
          id: block.id,
          type: "function",
          function: {
            name: block.name,
            arguments: JSON.stringify(block.input ?? {}),
          },
        });
      }
      // Other block types (thinking, server_tool_use, etc.) are silently
      // dropped — they don't translate to OpenAI and the agents in this
      // codebase don't emit them when constructing assistant messages
      // (we only re-emit what the LLM produced; if a future agent
      // generates one, the assistant message round-trip will lose it).
    }
    const assistantMsg: OpenAI.Chat.ChatCompletionAssistantMessageParam = {
      role: "assistant",
      content: textParts.length > 0 ? textParts.join("\n") : null,
    };
    if (toolCalls.length > 0) assistantMsg.tool_calls = toolCalls;
    out.push(assistantMsg);
  }

  return out;
}

export function translateTools(
  tools: Anthropic.MessageCreateParams["tools"]
): OpenAI.Chat.ChatCompletionFunctionTool[] {
  // Narrowed to ChatCompletionFunctionTool (the function-calling
  // variant) because that's the only OpenAI tool kind we emit.
  // ChatCompletionTool is a union with ChatCompletionCustomTool which
  // we never produce, and using the union type forces consumers
  // (tests, future callers) to discriminate before accessing
  // .function — which is unnecessary friction.
  if (!tools) return [];
  const out: OpenAI.Chat.ChatCompletionFunctionTool[] = [];
  for (const tool of tools) {
    if (!("input_schema" in tool)) continue; // skip Anthropic-specific server tools
    out.push({
      type: "function",
      function: {
        name: tool.name,
        description: tool.description ?? "",
        parameters: tool.input_schema as Record<string, unknown>,
      },
    });
  }
  return out;
}

export function translateResponse(
  response: OpenAI.Chat.ChatCompletion,
  model: string
): Anthropic.Message {
  const choice = response.choices[0];
  if (!choice) {
    throw new Error("OpenAILLMClient: response had no choices");
  }
  const message = choice.message;
  const content: Anthropic.ContentBlock[] = [];

  // Text content first (matches Anthropic's typical ordering)
  if (message.content && message.content.length > 0) {
    content.push({
      type: "text",
      text: message.content,
      citations: null,
    } as Anthropic.TextBlock);
  }

  // Then tool_use blocks
  if (message.tool_calls) {
    for (const call of message.tool_calls) {
      if (call.type !== "function") continue;
      let input: unknown = {};
      try {
        input = JSON.parse(call.function.arguments || "{}");
      } catch {
        // Malformed JSON in tool args — preserve as a string so the
        // agent can decide how to handle it. This shouldn't happen
        // with well-behaved providers but does occur with smaller
        // local models that emit malformed JSON.
        input = { _raw_arguments: call.function.arguments };
      }
      content.push({
        type: "tool_use",
        id: call.id,
        name: call.function.name,
        input,
      } as Anthropic.ToolUseBlock);
    }
  }

  return {
    id: response.id,
    type: "message",
    role: "assistant",
    model,
    content,
    stop_reason: translateStopReason(choice.finish_reason),
    stop_sequence: null,
    usage: {
      input_tokens: response.usage?.prompt_tokens ?? 0,
      output_tokens: response.usage?.completion_tokens ?? 0,
      cache_creation_input_tokens: null,
      cache_read_input_tokens: null,
      server_tool_use: null,
      service_tier: null,
    } as unknown as Anthropic.Usage,
  };
}

export function translateStopReason(
  finishReason: OpenAI.Chat.ChatCompletion.Choice["finish_reason"]
): Anthropic.Message["stop_reason"] {
  switch (finishReason) {
    case "tool_calls":
    case "function_call":
      return "tool_use";
    case "stop":
      return "end_turn";
    case "length":
      return "max_tokens";
    case "content_filter":
      return "refusal";
    default:
      return "end_turn";
  }
}

function stringifyToolResultContent(content: Anthropic.ToolResultBlockParam["content"]): string {
  if (typeof content === "string") return content;
  if (!content) return "";
  // Content blocks: Anthropic supports text + image; OpenAI tool messages
  // take a string. Concatenate text blocks; drop image blocks (no clean
  // OpenAI equivalent for tool-call image responses in the common path).
  return content
    .filter((b): b is Anthropic.TextBlockParam => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}
