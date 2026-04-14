export interface ToolDefinition {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export interface ToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface ProviderResponse {
  text: string | null;
  toolCalls: ToolCall[];
  done: boolean;
  usage: {
    inputTokens: number;
    outputTokens: number;
  };
}

export interface ToolResult {
  toolCallId: string;
  content: string;
}

export interface ProviderMessage {
  role: "user" | "assistant" | "tool_results";
  content: string | ToolCall[] | ToolResult[];
}

export interface AIProvider {
  name: string;

  chat(
    system: string,
    messages: ProviderMessage[],
    tools?: ToolDefinition[],
    maxTokens?: number
  ): Promise<ProviderResponse>;

  /** Cost per 1M input tokens in USD */
  inputCostPer1M: number;
  /** Cost per 1M output tokens in USD */
  outputCostPer1M: number;
}

export interface UsageTracker {
  inputTokens: number;
  outputTokens: number;
  requests: number;
  costUsd: number;
}

export function createUsageTracker(): UsageTracker {
  return { inputTokens: 0, outputTokens: 0, requests: 0, costUsd: 0 };
}

export function trackUsage(
  tracker: UsageTracker,
  provider: AIProvider,
  usage: { inputTokens: number; outputTokens: number }
): void {
  tracker.inputTokens += usage.inputTokens;
  tracker.outputTokens += usage.outputTokens;
  tracker.requests += 1;
  tracker.costUsd +=
    (usage.inputTokens / 1_000_000) * provider.inputCostPer1M +
    (usage.outputTokens / 1_000_000) * provider.outputCostPer1M;
}
