import { runTool, checkTool } from "./tool-runner.js";
import type { Vulnerability, Severity } from "../types/index.js";

interface GitleaksResult {
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  Match: string;
  Secret: string;
  RuleID: string;
  Entropy: number;
  Tags: string[];
}

export function isGitleaksInstalled(): boolean {
  return checkTool("gitleaks").installed;
}

export function runGitleaks(projectPath: string): Vulnerability[] {
  const args = [
    "detect",
    "--source", projectPath,
    "--report-format", "json",
    "--report-path", "/dev/stdout",
    "--no-git",
    "--exit-code", "0",
  ];

  const result = runTool<GitleaksResult[]>("gitleaks", args, {
    timeout: 120_000,
  });

  if (!result.data) return [];

  return normalizeFindings(result.data);
}

function normalizeFindings(findings: GitleaksResult[]): Vulnerability[] {
  return findings.map((f, i) => ({
    id: `GLKS-${String(i + 1).padStart(4, "0")}`,
    rule: `gitleaks:${f.RuleID}`,
    title: f.Description || f.RuleID,
    description: `Secret detected by Gitleaks rule '${f.RuleID}'. Rotate this credential immediately.`,
    severity: "critical" as Severity,
    category: "secrets",
    cwe: "CWE-798",
    confidence: "high" as const,
    location: {
      file: f.File,
      line: f.StartLine,
      snippet: maskSecret(f.Match),
    },
  }));
}

function maskSecret(value: string): string {
  if (value.length <= 12) return value.slice(0, 3) + "***";
  return value.slice(0, 6) + "..." + value.slice(-4) + " (masked)";
}
