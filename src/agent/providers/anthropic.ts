import Anthropic from "@anthropic-ai/sdk";
import type {
  AIProvider,
  ProviderMessage,
  ProviderResponse,
  ToolDefinition,
  ToolCall,
} from "./base.js";

const MODEL_COSTS: Record<string, { input: number; output: number }> = {
  "claude-sonnet-4-20250514": { input: 3, output: 15 },
  "claude-opus-4-6-20260401": { input: 15, output: 75 },
  "claude-haiku-4-5-20251001": { input: 0.8, output: 4 },
};

export class AnthropicProvider implements AIProvider {
  name = "anthropic";
  inputCostPer1M: number;
  outputCostPer1M: number;

  private client: Anthropic;
  private model: string;

  constructor(apiKey: string, model: string) {
    this.client = new Anthropic({ apiKey });
    this.model = model;
    const costs = MODEL_COSTS[model] || { input: 3, output: 15 };
    this.inputCostPer1M = costs.input;
    this.outputCostPer1M = costs.output;
  }

  async chat(
    system: string,
    messages: ProviderMessage[],
    tools?: ToolDefinition[],
    maxTokens = 4096
  ): Promise<ProviderResponse> {
    const anthropicMessages = this.convertMessages(messages);
    const anthropicTools = tools?.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema as Anthropic.Tool["input_schema"],
    }));

    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: maxTokens,
      system,
      messages: anthropicMessages,
      ...(anthropicTools && anthropicTools.length > 0 ? { tools: anthropicTools } : {}),
    });

    const toolCalls: ToolCall[] = [];
    let text: string | null = null;

    for (const block of response.content) {
      if (block.type === "text") {
        text = block.text;
      } else if (block.type === "tool_use") {
        toolCalls.push({
          id: block.id,
          name: block.name,
          input: block.input as Record<string, unknown>,
        });
      }
    }

    return {
      text,
      toolCalls,
      done: response.stop_reason !== "tool_use",
      usage: {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens,
      },
    };
  }

  private convertMessages(messages: ProviderMessage[]): Anthropic.MessageParam[] {
    const result: Anthropic.MessageParam[] = [];

    for (const msg of messages) {
      if (msg.role === "user") {
        result.push({ role: "user", content: msg.content as string });
      } else if (msg.role === "assistant") {
        if (typeof msg.content === "string") {
          result.push({ role: "assistant", content: msg.content });
        } else {
          // Tool calls from assistant
          const blocks: Anthropic.ContentBlock[] = (msg.content as ToolCall[]).map((tc) => ({
            type: "tool_use" as const,
            id: tc.id,
            name: tc.name,
            input: tc.input,
          }));
          result.push({ role: "assistant", content: blocks });
        }
      } else if (msg.role === "tool_results") {
        const results = msg.content as Array<{
          toolCallId: string;
          content: string;
        }>;
        result.push({
          role: "user",
          content: results.map((r) => ({
            type: "tool_result" as const,
            tool_use_id: r.toolCallId,
            content: r.content,
          })),
        });
      }
    }

    return result;
  }
}
