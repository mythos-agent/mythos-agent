import { runTool, checkTool } from "./tool-runner.js";
import type { Vulnerability, Severity } from "../types/index.js";

interface SemgrepResult {
  results: Array<{
    check_id: string;
    path: string;
    start: { line: number; col: number };
    end: { line: number; col: number };
    extra: {
      message: string;
      severity: string;
      metadata?: {
        cwe?: string[];
        confidence?: string;
        category?: string;
      };
      lines?: string;
    };
  }>;
  errors: unknown[];
}

export function isSemgrepInstalled(): boolean {
  return checkTool("semgrep").installed;
}

export function runSemgrep(
  projectPath: string,
  config?: string
): Vulnerability[] {
  const args = [
    "--json",
    "--quiet",
    "--no-git-ignore",
    "--config",
    config || "auto",
    projectPath,
  ];

  const result = runTool<SemgrepResult>("semgrep", args, {
    timeout: 300_000, // 5 min
  });

  if (!result.success || !result.data) return [];

  return normalizeFindings(result.data);
}

function normalizeFindings(data: SemgrepResult): Vulnerability[] {
  return data.results.map((r, i) => {
    const severity = mapSeverity(r.extra.severity);
    const cweList = r.extra.metadata?.cwe || [];

    return {
      id: `SGRP-${String(i + 1).padStart(4, "0")}`,
      rule: `semgrep:${r.check_id}`,
      title: r.check_id.split(".").pop() || r.check_id,
      description: r.extra.message,
      severity,
      category: r.extra.metadata?.category || "semgrep",
      cwe: cweList[0],
      confidence: (r.extra.metadata?.confidence as "high" | "medium" | "low") || "medium",
      location: {
        file: r.path,
        line: r.start.line,
        column: r.start.col,
        snippet: r.extra.lines?.trim(),
      },
    };
  });
}

function mapSeverity(s: string): Severity {
  switch (s.toUpperCase()) {
    case "ERROR": return "high";
    case "WARNING": return "medium";
    case "INFO": return "low";
    default: return "medium";
  }
}
