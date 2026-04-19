import Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig } from "../types/index.js";
import { createAgentTools, executeToolCall } from "./tools.js";

const QUERY_SYSTEM_PROMPT = `You are mythos-agent, an expert AI security analyst. The user is asking security questions about their codebase. You have access to tools to read files, search code, and list files.

## How to respond

1. Use the tools to explore the codebase and find relevant code
2. Answer the user's question with specific file paths, line numbers, and code snippets
3. If you find vulnerabilities, explain the risk and suggest fixes
4. Be concise but thorough — show evidence from the actual code

## Security expertise

You specialize in:
- Identifying unvalidated user inputs and injection points
- Tracing data flow from sources (user input) to sinks (dangerous operations)
- Finding authentication and authorization flaws
- Detecting race conditions and TOCTOU vulnerabilities
- Identifying information disclosure and error handling issues
- Reviewing cryptographic implementations
- Assessing API security (rate limiting, input validation, error handling)

Always cite specific files and line numbers. If you need to read more code to answer accurately, use the tools.`;

const MAX_TURNS = 15;

const MAX_HISTORY_TURNS = 10;

export class QueryEngine {
  private client: Anthropic;
  private model: string;
  private conversationHistory: Anthropic.MessageParam[] = [];

  constructor(
    private config: MythosConfig,
    private projectPath: string
  ) {
    this.client = new Anthropic({ apiKey: config.apiKey });
    this.model = config.model;
  }

  async query(question: string): Promise<string> {
    const tools = createAgentTools(this.projectPath);

    this.conversationHistory.push({
      role: "user",
      content: question,
    });

    let turns = 0;
    const messages = [...this.conversationHistory];

    while (turns < MAX_TURNS) {
      turns++;

      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 4096,
        temperature: 0,
        system: QUERY_SYSTEM_PROMPT,
        tools,
        messages,
      });

      if (response.stop_reason === "tool_use") {
        const assistantContent = response.content;
        messages.push({ role: "assistant", content: assistantContent });

        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const block of assistantContent) {
          if (block.type === "tool_use") {
            const result = executeToolCall(
              this.projectPath,
              block.name,
              block.input as Record<string, unknown>
            );
            toolResults.push({
              type: "tool_result",
              tool_use_id: block.id,
              content: result,
            });
          }
        }
        messages.push({ role: "user", content: toolResults });
        continue;
      }

      // Extract final text response
      const textBlock = response.content.find((b) => b.type === "text");
      if (textBlock && textBlock.type === "text") {
        // Update conversation history with the final exchange
        this.conversationHistory.push({
          role: "assistant",
          content: textBlock.text,
        });
        // Trim history to avoid unbounded context growth
        if (this.conversationHistory.length > MAX_HISTORY_TURNS * 2) {
          this.conversationHistory = this.conversationHistory.slice(-(MAX_HISTORY_TURNS * 2));
        }
        return textBlock.text;
      }

      break;
    }

    return "I wasn't able to answer that question. Try rephrasing or being more specific.";
  }

  clearHistory(): void {
    this.conversationHistory = [];
  }
}
