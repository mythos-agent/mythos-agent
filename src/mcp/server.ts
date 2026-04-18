#!/usr/bin/env node

/**
 * mythos-agent MCP Server
 *
 * Exposes mythos-agent capabilities as MCP tools that can be used by
 * Claude Code, Cursor, Copilot, and any MCP-compatible AI tool.
 *
 * Usage:
 *   npx mythos-agent mcp                    # start MCP server (stdio)
 *   Add to claude_desktop_config.json:
 *   {
 *     "mcpServers": {
 *       "mythos-agent": {
 *         "command": "npx",
 *         "args": ["mythos-agent", "mcp"]
 *       }
 *     }
 *   }
 */

import { loadConfig } from "../config/config.js";
import { PatternScanner } from "../scanner/pattern-scanner.js";
import { SecretsScanner } from "../scanner/secrets-scanner.js";
import { IacScanner } from "../scanner/iac-scanner.js";
import { parseCodebase } from "../analysis/code-parser.js";
import { mapEndpoints, assessEndpointSecurity } from "../analysis/endpoint-mapper.js";
import { loadResults } from "../store/results-store.js";
import type { Vulnerability } from "../types/index.js";
import { VERSION } from "../version.js";

interface McpRequest {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: Record<string, unknown>;
}

interface McpResponse {
  jsonrpc: "2.0";
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

const TOOLS = [
  {
    name: "sphinx_scan",
    description:
      "Scan a project for security vulnerabilities. Returns findings with severity, location, and description.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Project path to scan (default: current directory)" },
        severity: {
          type: "string",
          description: "Minimum severity: critical, high, medium, low",
          default: "low",
        },
      },
    },
  },
  {
    name: "sphinx_secrets",
    description: "Scan for hardcoded secrets, API keys, passwords, and tokens in source code.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Project path to scan" },
      },
    },
  },
  {
    name: "sphinx_endpoints",
    description:
      "Discover all API endpoints in the codebase and assess their security (auth status, risk level).",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Project path to analyze" },
      },
    },
  },
  {
    name: "sphinx_iac",
    description: "Scan Docker, Terraform, and Kubernetes files for security misconfigurations.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Project path to scan" },
      },
    },
  },
  {
    name: "sphinx_results",
    description:
      "Get the latest scan results for a project. Returns all findings, chains, and trust score.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Project path" },
      },
    },
  },
  {
    name: "sphinx_score",
    description: "Get a security score (0-100) with letter grade for the project.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Project path" },
      },
    },
  },
];

export async function startMcpServer(): Promise<void> {
  let buffer = "";

  process.stdin.setEncoding("utf-8");
  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;

    // Process complete JSON-RPC messages (newline-delimited)
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const request = JSON.parse(line) as McpRequest;
        handleRequest(request).then((response) => {
          process.stdout.write(JSON.stringify(response) + "\n");
        });
      } catch {
        // ignore malformed messages
      }
    }
  });

  // Send server info on startup
  process.stderr.write("mythos-agent MCP server started\n");
}

async function handleRequest(req: McpRequest): Promise<McpResponse> {
  switch (req.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id: req.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "mythos-agent", version: VERSION },
        },
      };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id: req.id,
        result: { tools: TOOLS },
      };

    case "tools/call":
      return handleToolCall(req);

    case "notifications/initialized":
      return { jsonrpc: "2.0", id: req.id, result: {} };

    default:
      return {
        jsonrpc: "2.0",
        id: req.id,
        error: { code: -32601, message: `Method not found: ${req.method}` },
      };
  }
}

async function handleToolCall(req: McpRequest): Promise<McpResponse> {
  const params = req.params as { name: string; arguments: Record<string, string> };
  const toolName = params.name;
  const args = params.arguments || {};
  const projectPath = args.path || process.cwd();

  try {
    let result: unknown;

    switch (toolName) {
      case "sphinx_scan": {
        const config = loadConfig(projectPath);
        const scanner = new PatternScanner(config);
        const { findings, filesScanned } = await scanner.scan(projectPath);
        const severity = args.severity || "low";
        const order = ["critical", "high", "medium", "low", "info"];
        const threshold = order.indexOf(severity);
        const filtered = findings.filter((f) => order.indexOf(f.severity) <= threshold);

        result = formatFindings(filtered, filesScanned);
        break;
      }

      case "sphinx_secrets": {
        const scanner = new SecretsScanner();
        const { findings } = await scanner.scan(projectPath);
        result = formatFindings(findings, 0);
        break;
      }

      case "sphinx_endpoints": {
        const map = await parseCodebase(projectPath);
        const endpoints = mapEndpoints(map);
        const assessment = assessEndpointSecurity(endpoints);

        result =
          `Endpoints: ${assessment.total}\nAuthenticated: ${assessment.authenticated}\nUnauthenticated: ${assessment.unauthenticated}\nHigh Risk: ${assessment.highRisk.length}\n\n${assessment.summary}\n\n` +
          endpoints
            .map(
              (e) =>
                `${e.method.padEnd(7)} ${e.path} — Auth: ${e.hasAuth ? "Yes" : "NO"} — Risk: ${e.riskLevel}`
            )
            .join("\n");
        break;
      }

      case "sphinx_iac": {
        const scanner = new IacScanner();
        const { findings } = await scanner.scan(projectPath);
        result = formatFindings(findings, 0);
        break;
      }

      case "sphinx_results": {
        const scanResult = loadResults(projectPath);
        if (!scanResult) {
          result = "No scan results found. Run `mythos-agent scan` first.";
        } else {
          const vulns = scanResult.confirmedVulnerabilities;
          result =
            `Last scan: ${scanResult.timestamp}\nFindings: ${vulns.length}\nChains: ${scanResult.chains.length}\n\n` +
            formatFindings(vulns, scanResult.filesScanned);
        }
        break;
      }

      case "sphinx_score": {
        const config = loadConfig(projectPath);
        const scanner = new PatternScanner(config);
        const { findings } = await scanner.scan(projectPath, false);
        const ss = new SecretsScanner();
        const { findings: sf } = await ss.scan(projectPath);
        const all = [...findings, ...sf];

        let score = 100;
        for (const f of all) {
          switch (f.severity) {
            case "critical":
              score -= 20;
              break;
            case "high":
              score -= 10;
              break;
            case "medium":
              score -= 4;
              break;
            case "low":
              score -= 1;
              break;
          }
        }
        score = Math.max(0, score);
        const grade =
          score >= 90
            ? "A+"
            : score >= 80
              ? "A"
              : score >= 70
                ? "B"
                : score >= 60
                  ? "C"
                  : score >= 50
                    ? "D"
                    : "F";

        result = `Security Score: ${score}/100 (${grade})\nFindings: ${all.length} (${findings.length} code + ${sf.length} secrets)`;
        break;
      }

      default:
        return {
          jsonrpc: "2.0",
          id: req.id,
          error: { code: -32602, message: `Unknown tool: ${toolName}` },
        };
    }

    return {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        content: [
          {
            type: "text",
            text: typeof result === "string" ? result : JSON.stringify(result, null, 2),
          },
        ],
      },
    };
  } catch (err) {
    return {
      jsonrpc: "2.0",
      id: req.id,
      result: {
        content: [
          { type: "text", text: `Error: ${err instanceof Error ? err.message : "unknown"}` },
        ],
        isError: true,
      },
    };
  }
}

function formatFindings(findings: Vulnerability[], filesScanned: number): string {
  if (findings.length === 0)
    return filesScanned > 0
      ? `Scanned ${filesScanned} files. No vulnerabilities found.`
      : "No vulnerabilities found.";

  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };

  let text = `Found ${findings.length} vulnerabilities`;
  if (filesScanned > 0) text += ` in ${filesScanned} files`;
  text += `\nCritical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}\n\n`;

  for (const f of findings.slice(0, 20)) {
    text += `[${f.severity.toUpperCase()}] ${f.id}: ${f.title}\n`;
    text += `  File: ${f.location.file}:${f.location.line}\n`;
    if (f.location.snippet) text += `  Code: ${f.location.snippet}\n`;
    text += `  ${f.description}\n\n`;
  }

  if (findings.length > 20) text += `...and ${findings.length - 20} more\n`;

  return text;
}
