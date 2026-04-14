import Anthropic from "@anthropic-ai/sdk";
import type { SphinxConfig } from "../types/index.js";
import type { ReconReport } from "./agent-protocol.js";
import { createAgentTools, executeToolCall } from "../agent/tools.js";

const RECON_SYSTEM = `You are a security reconnaissance agent. Your job is to map the attack surface of a codebase.

Use the tools to explore the project and identify:
1. **Entry points**: API routes, HTTP handlers, CLI commands, event listeners, WebSocket handlers
2. **Tech stack**: frameworks, languages, databases, auth libraries
3. **Authentication boundaries**: where auth checks happen, what's protected vs public
4. **Data stores**: databases, file storage, caches, external APIs

Output JSON:
{
  "entryPoints": [{"path": "/api/users", "method": "GET", "file": "src/routes.ts", "line": 12, "description": "List users endpoint"}],
  "techStack": ["express", "typescript", "postgresql"],
  "authBoundaries": [{"file": "src/middleware/auth.ts", "line": 5, "description": "JWT verification middleware"}],
  "dataStores": [{"type": "postgresql", "file": "src/db.ts", "description": "Main application database"}],
  "attackSurface": "Brief summary of the application's attack surface"
}`;

const MAX_TURNS = 15;

export class ReconAgent {
  private client: Anthropic;

  constructor(
    private config: SphinxConfig,
    private projectPath: string
  ) {
    this.client = new Anthropic({ apiKey: config.apiKey });
  }

  async execute(): Promise<ReconReport> {
    if (!this.config.apiKey) {
      return this.fallbackRecon();
    }

    const tools = createAgentTools(this.projectPath);
    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content: "Map the attack surface of this project. List files first, then explore entry points, auth boundaries, and data stores.",
      },
    ];

    let turns = 0;
    while (turns < MAX_TURNS) {
      turns++;
      const response = await this.client.messages.create({
        model: this.config.model,
        max_tokens: 4096,
        system: RECON_SYSTEM,
        tools,
        messages,
      });

      if (response.stop_reason === "tool_use") {
        messages.push({ role: "assistant", content: response.content });
        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const block of response.content) {
          if (block.type === "tool_use") {
            toolResults.push({
              type: "tool_result",
              tool_use_id: block.id,
              content: executeToolCall(
                this.projectPath,
                block.name,
                block.input as Record<string, unknown>
              ),
            });
          }
        }
        messages.push({ role: "user", content: toolResults });
        continue;
      }

      const text = response.content.find((b) => b.type === "text");
      if (text && text.type === "text") {
        return this.parseRecon(text.text);
      }
      break;
    }

    return this.fallbackRecon();
  }

  private parseRecon(text: string): ReconReport {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return this.fallbackRecon();

    try {
      const data = JSON.parse(jsonMatch[0]);
      return {
        type: "recon",
        entryPoints: data.entryPoints || [],
        techStack: data.techStack || [],
        authBoundaries: data.authBoundaries || [],
        dataStores: data.dataStores || [],
        attackSurface: data.attackSurface || "Unknown",
      };
    } catch {
      return this.fallbackRecon();
    }
  }

  private fallbackRecon(): ReconReport {
    return {
      type: "recon",
      entryPoints: [],
      techStack: [],
      authBoundaries: [],
      dataStores: [],
      attackSurface: "Reconnaissance requires AI. Run with API key configured.",
    };
  }
}
