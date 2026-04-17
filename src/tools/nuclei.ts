import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { runTool, checkTool } from "./tool-runner.js";
import type { Vulnerability, Severity } from "../types/index.js";

interface NucleiResult {
  "template-id": string;
  info: {
    name: string;
    description?: string;
    severity: string;
    tags?: string[];
    classification?: {
      "cve-id"?: string[];
      "cwe-id"?: string[];
    };
  };
  host: string;
  matched_at?: string;
  matcher_name?: string;
  extracted_results?: string[];
  curl_command?: string;
}

export function isNucleiInstalled(): boolean {
  return checkTool("nuclei").installed;
}

/**
 * Run Nuclei against a live target URL.
 */
export function runNuclei(
  target: string,
  options: {
    templates?: string[];
    severity?: string;
    tags?: string[];
    timeout?: number;
  } = {}
): Vulnerability[] {
  const args = ["-u", target, "-jsonl", "-silent", "-no-color"];

  if (options.severity) {
    args.push("-severity", options.severity);
  }
  if (options.tags && options.tags.length > 0) {
    args.push("-tags", options.tags.join(","));
  }
  if (options.templates) {
    for (const t of options.templates) {
      args.push("-t", t);
    }
  }

  const result = runTool<NucleiResult[]>("nuclei", args, {
    timeout: options.timeout || 300_000,
  });

  if (!result.data) return [];
  return normalizeFindings(result.data);
}

/**
 * Run Nuclei against multiple targets.
 */
export function runNucleiBulk(
  targets: string[],
  options: { severity?: string; tags?: string[] } = {}
): Vulnerability[] {
  if (targets.length === 0) return [];

  // Write targets to a temp file for Nuclei's -list flag
  const listFile = path.join(os.tmpdir(), `sphinx-nuclei-${crypto.randomUUID()}.txt`);
  fs.writeFileSync(listFile, targets.join("\n"), "utf-8");

  const args = ["-list", listFile, "-jsonl", "-silent", "-no-color"];

  if (options.severity) {
    args.push("-severity", options.severity);
  }

  try {
    const result = runTool<NucleiResult[]>("nuclei", args, {
      timeout: 600_000,
    });

    if (!result.data) return [];
    return normalizeFindings(result.data);
  } finally {
    try {
      fs.unlinkSync(listFile);
    } catch {
      /* ignore */
    }
  }
}

function normalizeFindings(findings: NucleiResult[]): Vulnerability[] {
  return findings.map((f, i) => {
    const cves = f.info.classification?.["cve-id"] || [];
    const cwes = f.info.classification?.["cwe-id"] || [];

    return {
      id: `NUCL-${String(i + 1).padStart(4, "0")}`,
      rule: `nuclei:${f["template-id"]}`,
      title: f.info.name,
      description: f.info.description || f.info.name,
      severity: mapSeverity(f.info.severity),
      category: "dast",
      cwe: cwes[0] || cves[0],
      confidence: "high" as const,
      location: {
        file: f.host,
        line: 0,
        snippet: f.matched_at || f.host,
      },
    };
  });
}

function mapSeverity(s: string): Severity {
  switch (s.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
      return "info";
    default:
      return "medium";
  }
}
