import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
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
  // Use temp file for report (cross-platform — /dev/stdout doesn't exist on Windows)
  const reportPath = path.join(os.tmpdir(), `sphinx-gitleaks-${crypto.randomUUID()}.json`);

  const args = [
    "detect",
    "--source",
    projectPath,
    "--report-format",
    "json",
    "--report-path",
    reportPath,
    "--no-git",
    "--exit-code",
    "0",
  ];

  try {
    runTool("gitleaks", args, { timeout: 120_000, parseJson: false });

    if (!fs.existsSync(reportPath)) return [];
    const raw = fs.readFileSync(reportPath, "utf-8");
    if (!raw.trim()) return [];

    const data = JSON.parse(raw) as GitleaksResult[];
    return normalizeFindings(data);
  } catch {
    return [];
  } finally {
    try {
      fs.unlinkSync(reportPath);
    } catch {
      /* ignore */
    }
  }
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
