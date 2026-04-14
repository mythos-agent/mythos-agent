import { runTool, checkTool } from "./tool-runner.js";
import type { Vulnerability, Severity } from "../types/index.js";

interface CheckovResult {
  results: {
    passed_checks: unknown[];
    failed_checks: Array<{
      check_id: string;
      check_result: { result: string };
      check_type: string;
      file_path: string;
      file_line_range: [number, number];
      resource: string;
      guideline?: string;
      check_class?: string;
      description?: string[];
      short_description?: string;
      severity?: string;
    }>;
  };
}

export function isCheckovInstalled(): boolean {
  return checkTool("checkov").installed;
}

export function runCheckov(projectPath: string): Vulnerability[] {
  const args = [
    "-d", projectPath,
    "-o", "json",
    "--quiet",
    "--compact",
  ];

  const result = runTool<CheckovResult>("checkov", args, {
    timeout: 300_000,
  });

  if (!result.data) return [];
  return normalizeFindings(result.data, projectPath);
}

function normalizeFindings(
  data: CheckovResult,
  projectPath: string
): Vulnerability[] {
  const checks = data.results?.failed_checks || [];

  return checks.map((c, i) => {
    const filePath = c.file_path.startsWith("/")
      ? c.file_path.slice(1)
      : c.file_path;

    return {
      id: `CHKV-${String(i + 1).padStart(4, "0")}`,
      rule: `checkov:${c.check_id}`,
      title: c.short_description || c.check_id,
      description: c.guideline || (c.description || []).join(" ") || `Failed check ${c.check_id} on ${c.resource}`,
      severity: mapSeverity(c.severity || c.check_result.result),
      category: "iac",
      confidence: "high" as const,
      location: {
        file: filePath,
        line: c.file_line_range[0],
        snippet: `Resource: ${c.resource}`,
      },
    };
  });
}

function mapSeverity(s: string): Severity {
  switch (s.toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    case "FAILED": return "high";
    default: return "medium";
  }
}
