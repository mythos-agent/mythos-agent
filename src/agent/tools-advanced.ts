import type Anthropic from "@anthropic-ai/sdk";
import { parseCodebase, type CodebaseMap } from "../analysis/code-parser.js";
import {
  buildCallGraph,
  findCallers,
  findCallees,
  traceCallPaths,
  type CallGraph,
} from "../analysis/call-graph.js";
import {
  mapEndpoints,
  findUnprotectedEndpoints,
  assessEndpointSecurity,
} from "../analysis/endpoint-mapper.js";

// Per-project cache to avoid re-parsing on repeated tool calls within a session
const cache = new Map<string, { map: CodebaseMap; graph: CallGraph | null }>();

async function getCodebaseMap(projectPath: string): Promise<CodebaseMap> {
  const entry = cache.get(projectPath);
  if (entry) return entry.map;
  const map = await parseCodebase(projectPath);
  cache.set(projectPath, { map, graph: null });
  return map;
}

function getCallGraph(map: CodebaseMap, projectPath: string): CallGraph {
  const entry = cache.get(projectPath);
  if (entry?.graph) return entry.graph;
  const graph = buildCallGraph(map, projectPath);
  if (entry) entry.graph = graph;
  return graph;
}

/**
 * Create advanced analysis tools for the AI agent.
 * These give the agent deeper code understanding capabilities.
 */
export function createAdvancedTools(projectPath: string): Anthropic.Tool[] {
  return [
    {
      name: "list_functions",
      description:
        "List all functions/methods in the codebase or a specific file. Returns name, file, line, params, exported status.",
      input_schema: {
        type: "object" as const,
        properties: {
          file: {
            type: "string",
            description: "Filter to a specific file (optional)",
          },
          exported_only: {
            type: "boolean",
            description: "Only show exported functions (default: false)",
          },
        },
        required: [],
      },
    },
    {
      name: "list_endpoints",
      description:
        "List all API endpoints (HTTP routes) discovered in the codebase. Shows method, path, auth status, and risk level.",
      input_schema: {
        type: "object" as const,
        properties: {},
        required: [],
      },
    },
    {
      name: "find_callers",
      description:
        "Find all functions that call a specific function. Useful for tracing data flow and understanding impact.",
      input_schema: {
        type: "object" as const,
        properties: {
          function_name: {
            type: "string",
            description: "Name of the function to find callers for",
          },
          file: {
            type: "string",
            description: "File containing the function (optional, for disambiguation)",
          },
        },
        required: ["function_name"],
      },
    },
    {
      name: "find_callees",
      description:
        "Find all functions called by a specific function. Useful for understanding what a function does.",
      input_schema: {
        type: "object" as const,
        properties: {
          function_name: {
            type: "string",
            description: "Name of the function to find callees for",
          },
          file: {
            type: "string",
            description: "File containing the function (optional)",
          },
        },
        required: ["function_name"],
      },
    },
    {
      name: "trace_call_path",
      description:
        "Trace the call path between two functions. Shows how data/control flows from one function to another.",
      input_schema: {
        type: "object" as const,
        properties: {
          from_function: {
            type: "string",
            description: "Starting function (e.g., 'src/routes.ts:handleRequest')",
          },
          to_function: {
            type: "string",
            description: "Target function (e.g., 'src/db.ts:query')",
          },
        },
        required: ["from_function", "to_function"],
      },
    },
    {
      name: "find_unprotected_endpoints",
      description:
        "Find API endpoints that lack authentication middleware but handle sensitive operations.",
      input_schema: {
        type: "object" as const,
        properties: {},
        required: [],
      },
    },
    {
      name: "get_security_overview",
      description:
        "Get an overview of the codebase security posture: endpoint auth coverage, function count, tech stack.",
      input_schema: {
        type: "object" as const,
        properties: {},
        required: [],
      },
    },
  ];
}

/**
 * Execute an advanced tool call.
 */
export async function executeAdvancedToolCall(
  projectPath: string,
  toolName: string,
  toolInput: Record<string, unknown>
): Promise<string> {
  const map = await getCodebaseMap(projectPath);
  const graph = getCallGraph(map, projectPath);

  switch (toolName) {
    case "list_functions": {
      let funcs = map.functions;
      const file = toolInput.file as string | undefined;
      if (file) funcs = funcs.filter((f) => f.file.includes(file));
      if (toolInput.exported_only) funcs = funcs.filter((f) => f.exported);

      if (funcs.length === 0) return "No functions found.";
      return funcs
        .slice(0, 50)
        .map(
          (f) =>
            `${f.exported ? "export " : ""}${f.async ? "async " : ""}${f.kind} ${f.name}(${f.params.join(", ")})\n  ${f.file}:${f.line}`
        )
        .join("\n\n");
    }

    case "list_endpoints": {
      const endpoints = mapEndpoints(map);
      if (endpoints.length === 0) return "No API endpoints found.";

      return endpoints
        .map(
          (e) =>
            `${e.method.padEnd(7)} ${e.path}\n  File: ${e.file}:${e.line}\n  Auth: ${e.hasAuth ? `Yes (${e.authType})` : "NO"}\n  Risk: ${e.riskLevel}${e.riskReason ? ` — ${e.riskReason}` : ""}`
        )
        .join("\n\n");
    }

    case "find_callers": {
      const name = toolInput.function_name as string;
      const file = toolInput.file as string | undefined;

      const key = file ? `${file}:${name}` : null;
      let callerEdges;

      if (key) {
        callerEdges = findCallers(graph, key);
      } else {
        // Search all matching function names
        callerEdges = [...graph.callers.entries()]
          .filter(([k]) => k.endsWith(`:${name}`))
          .flatMap(([, edges]) => edges);
      }

      if (callerEdges.length === 0) return `No callers found for '${name}'.`;
      return (
        `Callers of '${name}':\n` +
        callerEdges
          .slice(0, 30)
          .map((e) => `  ${e.caller} → ${e.callee}  (${e.file}:${e.line})`)
          .join("\n")
      );
    }

    case "find_callees": {
      const name = toolInput.function_name as string;
      const file = toolInput.file as string | undefined;

      const key = file ? `${file}:${name}` : null;
      let calleeEdges;

      if (key) {
        calleeEdges = findCallees(graph, key);
      } else {
        calleeEdges = [...graph.callees.entries()]
          .filter(([k]) => k.endsWith(`:${name}`))
          .flatMap(([, edges]) => edges);
      }

      if (calleeEdges.length === 0) return `No callees found for '${name}'.`;
      return (
        `Functions called by '${name}':\n` +
        calleeEdges
          .slice(0, 30)
          .map((e) => `  ${e.caller} → ${e.callee}`)
          .join("\n")
      );
    }

    case "trace_call_path": {
      const from = toolInput.from_function as string;
      const to = toolInput.to_function as string;
      const paths = traceCallPaths(graph, from, to);

      if (paths.length === 0) return `No call path found from '${from}' to '${to}'.`;
      return (
        `Found ${paths.length} path(s):\n` +
        paths
          .slice(0, 5)
          .map((p, i) => `  Path ${i + 1}: ${p.join(" → ")}`)
          .join("\n")
      );
    }

    case "find_unprotected_endpoints": {
      const endpoints = mapEndpoints(map);
      const unprotected = findUnprotectedEndpoints(endpoints);

      if (unprotected.length === 0) return "No unprotected sensitive endpoints found.";
      return (
        `Found ${unprotected.length} unprotected endpoint(s):\n\n` +
        unprotected
          .map(
            (e) =>
              `⚠️ ${e.method} ${e.path}\n  File: ${e.file}:${e.line}\n  Risk: ${e.riskLevel} — ${e.riskReason}`
          )
          .join("\n\n")
      );
    }

    case "get_security_overview": {
      const endpoints = mapEndpoints(map);
      const assessment = assessEndpointSecurity(endpoints);

      return [
        `Codebase Security Overview:`,
        `  Functions: ${map.functions.length}`,
        `  Classes: ${map.classes.length}`,
        `  Imports: ${map.imports.length}`,
        `  API Endpoints: ${assessment.total}`,
        `    Authenticated: ${assessment.authenticated}`,
        `    Unauthenticated: ${assessment.unauthenticated}`,
        `    High-risk: ${assessment.highRisk.length}`,
        `  Routes: ${map.routes.length}`,
        `  Exports: ${map.exports.length}`,
        ``,
        `  ${assessment.summary}`,
      ].join("\n");
    }

    default:
      return `Unknown tool: ${toolName}`;
  }
}
