import http from "node:http";
import { URL } from "node:url";
import path from "node:path";
import { loadConfig } from "../config/config.js";
import { PatternScanner } from "../scanner/pattern-scanner.js";
import { SecretsScanner } from "../scanner/secrets-scanner.js";
import { IacScanner } from "../scanner/iac-scanner.js";
import { DepScanner } from "../scanner/dep-scanner.js";
import { runAllTools } from "../tools/index.js";
import { loadResults, saveResults } from "../store/results-store.js";
import { loadBaseline, compareToBaseline } from "../store/baseline.js";
import { loadPolicy, evaluatePolicy } from "../policy/engine.js";
import { renderSarifReport } from "../report/sarif-reporter.js";
import { renderMarkdownReport } from "../report/markdown-reporter.js";
import type { Vulnerability, ScanResult } from "../types/index.js";

interface ServerConfig {
  port: number;
  host: string;
  projectPath: string;
  apiKey?: string;
}

type RouteHandler = (
  req: http.IncomingMessage,
  params: Record<string, string>,
  body: string
) => Promise<{ status: number; data: unknown }>;

const routes: Array<{
  method: string;
  path: string;
  handler: RouteHandler;
}> = [];

function route(method: string, routePath: string, handler: RouteHandler) {
  routes.push({ method, path: routePath, handler });
}

// Module-level config set by createServer — single-instance only
let serverConfig: ServerConfig;

// === API Routes ===

route("GET", "/api/health", async () => ({
  status: 200,
  data: { status: "ok", version: "1.0.0", timestamp: new Date().toISOString() },
}));

route("GET", "/api/results", async () => {
  const result = loadResults(serverConfig.projectPath);
  return { status: result ? 200 : 404, data: result || { error: "No scan results" } };
});

route("GET", "/api/results/sarif", async () => {
  const result = loadResults(serverConfig.projectPath);
  if (!result) return { status: 404, data: { error: "No scan results" } };
  return { status: 200, data: JSON.parse(renderSarifReport(result)) };
});

route("GET", "/api/results/markdown", async () => {
  const result = loadResults(serverConfig.projectPath);
  if (!result) return { status: 404, data: { error: "No scan results" } };
  return {
    status: 200,
    data: { markdown: renderMarkdownReport(result, serverConfig.projectPath) },
  };
});

route("GET", "/api/baseline", async () => {
  const result = loadResults(serverConfig.projectPath);
  if (!result) return { status: 404, data: { error: "No scan results" } };
  const diff = compareToBaseline(serverConfig.projectPath, result);
  if (!diff) return { status: 404, data: { error: "No baseline saved" } };
  return {
    status: 200,
    data: {
      newFindings: diff.newFindings.length,
      fixedFindings: diff.fixedFindings.length,
      unchanged: diff.unchangedCount,
    },
  };
});

route("GET", "/api/policy", async () => {
  const result = loadResults(serverConfig.projectPath);
  if (!result) return { status: 404, data: { error: "No scan results" } };
  const policy = loadPolicy(serverConfig.projectPath);
  if (!policy) return { status: 404, data: { error: "No policy configured" } };
  const policyResult = evaluatePolicy(policy, result);
  return { status: policyResult.passed ? 200 : 422, data: policyResult };
});

route("POST", "/api/scan", async (_req, _params, body) => {
  let options: Record<string, unknown> = {};
  if (body) {
    try {
      options = JSON.parse(body);
    } catch {
      return { status: 400, data: { error: "Invalid JSON body" } };
    }
  }
  // Restrict scanning to the configured project path (prevent path traversal)
  const projectPath = serverConfig.projectPath;

  const config = loadConfig(projectPath);
  const findings: Vulnerability[] = [];
  const startTime = Date.now();

  // Run built-in scanners
  const patternScanner = new PatternScanner(config);
  const { findings: patterns, filesScanned, languages } = await patternScanner.scan(projectPath);
  findings.push(...patterns);

  const secretsScanner = new SecretsScanner();
  const { findings: secrets } = await secretsScanner.scan(projectPath);
  findings.push(...secrets);

  const iacScanner = new IacScanner();
  const { findings: iac } = await iacScanner.scan(projectPath);
  findings.push(...iac);

  try {
    const depScanner = new DepScanner();
    const { findings: deps } = await depScanner.scan(projectPath);
    findings.push(...deps);
  } catch {
    /* optional */
  }

  // External tools
  const { findings: external, toolsRun } = await runAllTools(projectPath);
  findings.push(...external);

  const result: ScanResult = {
    projectPath,
    timestamp: new Date().toISOString(),
    duration: Date.now() - startTime,
    languages,
    filesScanned,
    phase1Findings: findings,
    phase2Findings: [],
    confirmedVulnerabilities: findings,
    dismissedCount: 0,
    chains: [],
  };

  saveResults(projectPath, result);

  return {
    status: 200,
    data: {
      findings: findings.length,
      filesScanned,
      languages,
      tools: ["built-in", ...toolsRun],
      duration: result.duration,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
    },
  };
});

route("GET", "/api/history", async () => {
  const historyPath = path.join(serverConfig.projectPath, ".sphinx", "history.json");
  const fs = await import("node:fs");
  if (!fs.existsSync(historyPath)) return { status: 200, data: { scans: [] } };
  try {
    const data = JSON.parse(fs.readFileSync(historyPath, "utf-8"));
    return { status: 200, data };
  } catch {
    return { status: 200, data: { scans: [] } };
  }
});

// === Server ===

const MAX_BODY_SIZE = 1024 * 1024; // 1MB limit

export function createServer(config: ServerConfig): http.Server {
  serverConfig = config;
  const activeConfig = config;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const method = req.method || "GET";

    // CORS — restrict to localhost only
    const origin = req.headers.origin || "";
    if (origin.startsWith("http://localhost") || origin.startsWith("http://127.0.0.1")) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // API key auth (optional)
    if (activeConfig.apiKey) {
      const authHeader = req.headers.authorization;
      if (authHeader !== `Bearer ${activeConfig.apiKey}`) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }
    }

    // Read body for POST with size limit
    let body = "";
    if (method === "POST") {
      body = await new Promise<string>((resolve, reject) => {
        const chunks: Buffer[] = [];
        let totalSize = 0;
        req.on("data", (chunk: Buffer) => {
          totalSize += chunk.length;
          if (totalSize > MAX_BODY_SIZE) {
            req.destroy();
            resolve("");
            return;
          }
          chunks.push(chunk);
        });
        req.on("end", () => resolve(Buffer.concat(chunks).toString()));
        req.on("error", () => resolve(""));
      });

      if (!body && req.destroyed) {
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
        return;
      }
    }

    // Match route
    const matched = routes.find((r) => r.method === method && r.path === url.pathname);

    if (matched) {
      try {
        const result = await matched.handler(req, {}, body);
        res.writeHead(result.status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result.data, null, 2));
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: err instanceof Error ? err.message : "Internal server error",
          })
        );
      }
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Not found",
          endpoints: routes.map((r) => `${r.method} ${r.path}`),
        })
      );
    }
  });

  return server;
}
