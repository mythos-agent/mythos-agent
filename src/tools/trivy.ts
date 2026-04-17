import { runTool, checkTool } from "./tool-runner.js";
import type { Vulnerability, Severity } from "../types/index.js";

interface TrivyResult {
  Results?: Array<{
    Target: string;
    Class: string;
    Type: string;
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      PkgName: string;
      InstalledVersion: string;
      FixedVersion?: string;
      Title?: string;
      Description?: string;
      Severity: string;
      References?: string[];
      CVSS?: Record<string, { V3Score?: number }>;
    }>;
    Misconfigurations?: Array<{
      ID: string;
      Title: string;
      Description: string;
      Severity: string;
      Resolution?: string;
      CauseMetadata?: {
        StartLine?: number;
        EndLine?: number;
        Code?: { Lines?: Array<{ Content: string }> };
      };
    }>;
    Secrets?: Array<{
      RuleID: string;
      Title: string;
      Severity: string;
      Match: string;
      StartLine: number;
    }>;
  }>;
}

export function isTrivyInstalled(): boolean {
  return checkTool("trivy").installed;
}

/**
 * Run Trivy filesystem scan (SCA + secrets + misconfig).
 */
export function runTrivyFs(projectPath: string): Vulnerability[] {
  const args = [
    "fs",
    "--format",
    "json",
    "--scanners",
    "vuln,misconfig,secret",
    "--quiet",
    projectPath,
  ];

  const result = runTool<TrivyResult>("trivy", args, {
    timeout: 300_000,
  });

  if (!result.data) return [];
  return normalizeFindings(result.data);
}

/**
 * Run Trivy container image scan.
 */
export function runTrivyImage(image: string): Vulnerability[] {
  const args = [
    "image",
    "--format",
    "json",
    "--scanners",
    "vuln,misconfig,secret",
    "--quiet",
    image,
  ];

  const result = runTool<TrivyResult>("trivy", args, {
    timeout: 300_000,
  });

  if (!result.data) return [];
  return normalizeFindings(result.data);
}

function normalizeFindings(data: TrivyResult): Vulnerability[] {
  const findings: Vulnerability[] = [];
  let counter = 1;

  for (const target of data.Results || []) {
    // SCA vulnerabilities
    for (const v of target.Vulnerabilities || []) {
      findings.push({
        id: `TRVY-${String(counter++).padStart(4, "0")}`,
        rule: `trivy:${v.VulnerabilityID}`,
        title: `${v.PkgName}@${v.InstalledVersion}: ${v.VulnerabilityID}`,
        description: v.Title || v.Description || `Known vulnerability in ${v.PkgName}`,
        severity: mapSeverity(v.Severity),
        category: "dependency",
        cwe: v.VulnerabilityID,
        confidence: "high",
        location: {
          file: target.Target,
          line: 0,
          snippet: `${v.PkgName}@${v.InstalledVersion}${v.FixedVersion ? ` → fix: ${v.FixedVersion}` : ""}`,
        },
      });
    }

    // Misconfigurations
    for (const m of target.Misconfigurations || []) {
      findings.push({
        id: `TRVY-${String(counter++).padStart(4, "0")}`,
        rule: `trivy:${m.ID}`,
        title: m.Title,
        description: m.Description,
        severity: mapSeverity(m.Severity),
        category: "iac",
        confidence: "high",
        location: {
          file: target.Target,
          line: m.CauseMetadata?.StartLine || 0,
          snippet: m.Resolution,
        },
      });
    }

    // Secrets
    for (const s of target.Secrets || []) {
      findings.push({
        id: `TRVY-${String(counter++).padStart(4, "0")}`,
        rule: `trivy:${s.RuleID}`,
        title: s.Title,
        description: `Secret detected by Trivy: ${s.Title}`,
        severity: mapSeverity(s.Severity),
        category: "secrets",
        cwe: "CWE-798",
        confidence: "high",
        location: {
          file: target.Target,
          line: s.StartLine,
          snippet: maskSecret(s.Match),
        },
      });
    }
  }

  return findings;
}

function mapSeverity(s: string): Severity {
  switch (s.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

function maskSecret(value: string): string {
  if (value.length <= 12) return value.slice(0, 3) + "***";
  return value.slice(0, 6) + "..." + value.slice(-4) + " (masked)";
}
