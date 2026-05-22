import type Anthropic from "@anthropic-ai/sdk";
import { createAgentTools, executeToolCall } from "./tools.js";
import { createAdvancedTools, executeAdvancedToolCall } from "./tools-advanced.js";

// Advanced-tool definitions are static (createAdvancedTools returns a
// fixed array independent of the project path), so the routing name set
// can be computed once at module load.
const ADVANCED_TOOL_NAMES: ReadonlySet<string> = new Set(
  createAdvancedTools("").map((t) => t.name)
);

/**
 * The full toolset for a hunt agent: the four basic grep/read tools
 * plus the advanced call-graph / endpoint tools. Replaces a bare
 * `createAgentTools` call so the recon/hypothesis/analyzer agents can
 * reason across function and file boundaries.
 */
export function createHuntAgentTools(projectPath: string): Anthropic.Tool[] {
  return [...createAgentTools(projectPath), ...createAdvancedTools(projectPath)];
}

/**
 * Dispatch a tool call to the correct executor by tool name: advanced
 * tool names route to `executeAdvancedToolCall`, everything else to the
 * basic `executeToolCall`.
 */
export function executeHuntToolCall(
  projectPath: string,
  toolName: string,
  toolInput: Record<string, unknown>
): Promise<string> {
  if (ADVANCED_TOOL_NAMES.has(toolName)) {
    return executeAdvancedToolCall(projectPath, toolName, toolInput);
  }
  return executeToolCall(projectPath, toolName, toolInput);
}
