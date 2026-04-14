import type {
  AIProvider,
  ProviderMessage,
  ProviderResponse,
  ToolDefinition,
  ToolCall,
} from "./base.js";

interface OpenAIMessage {
  role: "system" | "user" | "assistant" | "tool";
  content?: string | null;
  tool_calls?: Array<{
    id: string;
    type: "function";
    function: { name: string; arguments: string };
  }>;
  tool_call_id?: string;
}

interface OpenAITool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
}

interface OpenAIResponse {
  choices: Array<{
    message: {
      content: string | null;
      tool_calls?: Array<{
        id: string;
        function: { name: string; arguments: string };
      }>;
    };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
  };
}

/**
 * Provider for OpenAI and any OpenAI-compatible API (Ollama, vLLM, LM Studio, etc.)
 */
export class OpenAICompatibleProvider implements AIProvider {
  name: string;
  inputCostPer1M: number;
  outputCostPer1M: number;

  private apiKey: string;
  private model: string;
  private baseUrl: string;

  constructor(options: {
    name?: string;
    apiKey: string;
    model: string;
    baseUrl?: string;
    inputCostPer1M?: number;
    outputCostPer1M?: number;
  }) {
    this.name = options.name || "openai";
    this.apiKey = options.apiKey;
    this.model = options.model;
    this.baseUrl = options.baseUrl || "https://api.openai.com/v1";
    this.inputCostPer1M = options.inputCostPer1M || 2.5;
    this.outputCostPer1M = options.outputCostPer1M || 10;
  }

  async chat(
    system: string,
    messages: ProviderMessage[],
    tools?: ToolDefinition[],
    maxTokens = 4096
  ): Promise<ProviderResponse> {
    const openaiMessages: OpenAIMessage[] = [
      { role: "system", content: system },
      ...this.convertMessages(messages),
    ];

    const openaiTools: OpenAITool[] | undefined = tools?.map((t) => ({
      type: "function" as const,
      function: {
        name: t.name,
        description: t.description,
        parameters: t.input_schema,
      },
    }));

    const body: Record<string, unknown> = {
      model: this.model,
      messages: openaiMessages,
      max_tokens: maxTokens,
    };

    if (openaiTools && openaiTools.length > 0) {
      body.tools = openaiTools;
    }

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${this.name} API error (${response.status}): ${text}`);
    }

    const data = (await response.json()) as OpenAIResponse;
    const choice = data.choices[0];

    const toolCalls: ToolCall[] = (choice.message.tool_calls || []).map(
      (tc) => ({
        id: tc.id,
        name: tc.function.name,
        input: JSON.parse(tc.function.arguments),
      })
    );

    return {
      text: choice.message.content,
      toolCalls,
      done: choice.finish_reason !== "tool_calls",
      usage: {
        inputTokens: data.usage?.prompt_tokens || 0,
        outputTokens: data.usage?.completion_tokens || 0,
      },
    };
  }

  private convertMessages(messages: ProviderMessage[]): OpenAIMessage[] {
    const result: OpenAIMessage[] = [];

    for (const msg of messages) {
      if (msg.role === "user") {
        result.push({ role: "user", content: msg.content as string });
      } else if (msg.role === "assistant") {
        if (typeof msg.content === "string") {
          result.push({ role: "assistant", content: msg.content });
        } else {
          const toolCalls = (msg.content as ToolCall[]).map((tc) => ({
            id: tc.id,
            type: "function" as const,
            function: {
              name: tc.name,
              arguments: JSON.stringify(tc.input),
            },
          }));
          result.push({ role: "assistant", content: null, tool_calls: toolCalls });
        }
      } else if (msg.role === "tool_results") {
        const results = msg.content as Array<{
          toolCallId: string;
          content: string;
        }>;
        for (const r of results) {
          result.push({
            role: "tool",
            content: r.content,
            tool_call_id: r.toolCallId,
          });
        }
      }
    }

    return result;
  }
}
