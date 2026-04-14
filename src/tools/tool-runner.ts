import { spawnSync, type SpawnSyncReturns } from "node:child_process";

export interface ToolResult<T = unknown> {
  success: boolean;
  data: T | null;
  raw: string;
  error?: string;
  duration: number;
}

export interface ToolInfo {
  name: string;
  command: string;
  versionFlag: string;
  installed: boolean;
  version?: string;
}

const TOOL_COMMANDS: Record<string, { command: string; versionFlag: string }> = {
  semgrep: { command: "semgrep", versionFlag: "--version" },
  gitleaks: { command: "gitleaks", versionFlag: "version" },
  trivy: { command: "trivy", versionFlag: "--version" },
  checkov: { command: "checkov", versionFlag: "--version" },
  nuclei: { command: "nuclei", versionFlag: "-version" },
  nmap: { command: "nmap", versionFlag: "--version" },
  httpx: { command: "httpx", versionFlag: "-version" },
  sqlmap: { command: "sqlmap", versionFlag: "--version" },
};

/**
 * Run a tool as a subprocess and parse its JSON output.
 */
export function runTool<T = unknown>(
  command: string,
  args: string[],
  options: {
    cwd?: string;
    timeout?: number;
    parseJson?: boolean;
  } = {}
): ToolResult<T> {
  const { cwd, timeout = 120_000, parseJson = true } = options;
  const start = Date.now();

  const result: SpawnSyncReturns<string> = spawnSync(command, args, {
    cwd,
    encoding: "utf-8",
    timeout,
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 50 * 1024 * 1024, // 50MB
  });

  const duration = Date.now() - start;
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";

  if (result.error) {
    return {
      success: false,
      data: null,
      raw: stdout,
      error: result.error.message,
      duration,
    };
  }

  if (parseJson && stdout.trim()) {
    try {
      // Handle JSONL (one JSON per line) — common for Nuclei
      if (stdout.trim().startsWith("[") || stdout.trim().startsWith("{")) {
        const data = JSON.parse(stdout) as T;
        return { success: true, data, raw: stdout, duration };
      }

      // Try JSONL
      const lines = stdout.trim().split("\n").filter((l) => l.trim());
      const parsed = lines.map((l) => JSON.parse(l));
      return { success: true, data: parsed as T, raw: stdout, duration };
    } catch {
      // JSON parse failed — return raw
      return {
        success: result.status === 0,
        data: null,
        raw: stdout,
        error: stderr || "Failed to parse JSON output",
        duration,
      };
    }
  }

  return {
    success: result.status === 0,
    data: null,
    raw: stdout,
    error: stderr || undefined,
    duration,
  };
}

/**
 * Check if a tool is installed and return its version.
 */
export function checkTool(name: string): ToolInfo {
  const config = TOOL_COMMANDS[name];
  if (!config) {
    return { name, command: name, versionFlag: "", installed: false };
  }

  const result = spawnSync(config.command, [config.versionFlag], {
    encoding: "utf-8",
    timeout: 5000,
    stdio: ["pipe", "pipe", "pipe"],
  });

  const installed = result.status === 0 || !result.error;
  const version = (result.stdout || result.stderr || "")
    .trim()
    .split("\n")[0]
    .slice(0, 100);

  return {
    name,
    command: config.command,
    versionFlag: config.versionFlag,
    installed,
    version: installed ? version : undefined,
  };
}

/**
 * Check all known tools and return their status.
 */
export function checkAllTools(): ToolInfo[] {
  return Object.keys(TOOL_COMMANDS).map(checkTool);
}
