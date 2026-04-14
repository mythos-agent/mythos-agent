import Anthropic from "@anthropic-ai/sdk";
import type { MythohConfig, Vulnerability, Severity } from "../types/index.js";
import { createAgentTools, executeToolCall } from "./tools.js";

export interface TaintFlow {
  id: string;
  source: {
    description: string;
    file: string;
    line: number;
    snippet: string;
  };
  sink: {
    description: string;
    file: string;
    line: number;
    snippet: string;
  };
  intermediateSteps: Array<{
    description: string;
    file: string;
    line: number;
    snippet: string;
  }>;
  severity: Severity;
  narrative: string;
}

const TAINT_SYSTEM_PROMPT = `You are sphinx-agent's taint analysis engine. Your job is to trace the flow of user-controlled data from **sources** (where data enters the application) to **sinks** (where dangerous operations happen).

## Sources (where tainted data enters)
- HTTP request parameters: req.query, req.params, req.body, req.headers
- URL parameters, form data, file uploads
- Database reads that originated from user input
- Environment variables containing user-facing config
- WebSocket messages, API responses used as input

## Sinks (dangerous operations)
- SQL queries (SQL injection)
- Shell commands (command injection)
- File system operations (path traversal)
- HTML rendering (XSS)
- HTTP requests (SSRF)
- eval() / dynamic code execution
- Redirect URLs (open redirect)
- Deserialization

## Your task
1. Use the provided tools to read files, search code, and list files
2. Find all entry points (API routes, request handlers, etc.)
3. For each entry point, trace how user input flows through the code
4. Identify any paths where tainted data reaches a sink WITHOUT proper sanitization
5. Report each taint flow with the full path from source to sink

## Output Format
Respond with JSON:
{
  "flows": [
    {
      "source": {
        "description": "User input from req.query.name",
        "file": "src/routes/search.ts",
        "line": 12,
        "snippet": "const name = req.query.name"
      },
      "sink": {
        "description": "Unsanitized SQL query",
        "file": "src/db/queries.ts",
        "line": 45,
        "snippet": "db.query('SELECT * FROM users WHERE name = ' + name)"
      },
      "intermediateSteps": [
        {
          "description": "Passed to search function without validation",
          "file": "src/routes/search.ts",
          "line": 15,
          "snippet": "const results = await searchUsers(name)"
        }
      ],
      "severity": "critical",
      "narrative": "User input from the search query parameter flows directly to a SQL query without parameterization, enabling SQL injection."
    }
  ]
}`;

const MAX_TURNS = 25;

export class TaintTracker {
  private client: Anthropic;
  private model: string;

  constructor(private config: MythohConfig) {
    this.client = new Anthropic({ apiKey: config.apiKey });
    this.model = config.model;
  }

  async analyze(projectPath: string): Promise<TaintFlow[]> {
    const tools = createAgentTools(projectPath);

    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content: `Perform a comprehensive taint analysis on this project.

1. First, list the project files to understand the structure
2. Find all entry points (API routes, request handlers, WebSocket handlers)
3. For each entry point, trace user input through the code to identify taint flows
4. Report all paths where user-controlled data reaches a dangerous sink without sanitization

Be thorough — follow imports, function calls, and data transformations across files.`,
      },
    ];

    let turns = 0;
    while (turns < MAX_TURNS) {
      turns++;

      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 8192,
        system: TAINT_SYSTEM_PROMPT,
        tools,
        messages,
      });

      if (response.stop_reason === "tool_use") {
        messages.push({ role: "assistant", content: response.content });

        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const block of response.content) {
          if (block.type === "tool_use") {
            const result = executeToolCall(
              projectPath,
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

      const textBlock = response.content.find((b) => b.type === "text");
      if (textBlock && textBlock.type === "text") {
        return this.parseFlows(textBlock.text);
      }

      break;
    }

    return [];
  }

  private parseFlows(text: string): TaintFlow[] {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return [];

    let output: {
      flows: Array<{
        source: { description: string; file: string; line: number; snippet: string };
        sink: { description: string; file: string; line: number; snippet: string };
        intermediateSteps?: Array<{ description: string; file: string; line: number; snippet: string }>;
        severity: Severity;
        narrative: string;
      }>;
    };

    try {
      output = JSON.parse(jsonMatch[0]);
    } catch {
      return [];
    }

    return (output.flows || []).map((flow, i) => ({
      id: `TAINT-${String(i + 1).padStart(3, "0")}`,
      source: flow.source,
      sink: flow.sink,
      intermediateSteps: flow.intermediateSteps || [],
      severity: flow.severity,
      narrative: flow.narrative,
    }));
  }
}
