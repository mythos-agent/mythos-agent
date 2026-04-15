import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { saveResults } from "../../store/results-store.js";
import type { Vulnerability, ScanResult, Severity } from "../../types/index.js";

interface ImportOptions {
  path?: string;
  format: string;
}

export async function importCommand(filePath: string, options: ImportOptions) {
  const absPath = path.resolve(filePath);
  const projectPath = path.resolve(options.path || ".");

  if (!fs.existsSync(absPath)) {
    console.log(chalk.yellow(`\n⚠️  File not found: ${absPath}\n`));
    return;
  }

  const content = fs.readFileSync(absPath, "utf-8");
  let findings: Vulnerability[] = [];

  switch (options.format) {
    case "sarif":
      findings = importSarif(content);
      break;
    case "semgrep":
      findings = importSemgrep(content);
      break;
    case "snyk":
      findings = importSnyk(content);
      break;
    case "trivy":
      findings = importTrivy(content);
      break;
    default:
      // Auto-detect
      if (content.includes('"$schema"') && content.includes("sarif")) {
        findings = importSarif(content);
      } else if (content.includes('"results"') && content.includes("check_id")) {
        findings = importSemgrep(content);
      } else if (content.includes('"vulnerabilities"') && content.includes("snyk")) {
        findings = importSnyk(content);
      } else {
        console.log(chalk.yellow("\n⚠️  Could not auto-detect format. Use --format flag.\n"));
        return;
      }
  }

  if (findings.length === 0) {
    console.log(chalk.yellow("\n⚠️  No findings imported.\n"));
    return;
  }

  // Save as sphinx-agent results
  const result: ScanResult = {
    projectPath,
    timestamp: new Date().toISOString(),
    duration: 0,
    languages: [],
    filesScanned: 0,
    phase1Findings: findings,
    phase2Findings: [],
    confirmedVulnerabilities: findings,
    dismissedCount: 0,
    chains: [],
  };

  saveResults(projectPath, result);
  console.log(chalk.green(`\n✅ Imported ${findings.length} findings from ${options.format || "auto-detected"} format.\n`));
  console.log(chalk.dim("  Run sphinx-agent report to view, or sphinx-agent fix to generate patches.\n"));
}

function importSarif(content: string): Vulnerability[] {
  const data = JSON.parse(content);
  const findings: Vulnerability[] = [];
  let id = 1;

  for (const run of data.runs || []) {
    for (const result of run.results || []) {
      const loc = result.locations?.[0]?.physicalLocation;
      findings.push({
        id: `IMP-${String(id++).padStart(4, "0")}`,
        rule: `imported:${result.ruleId || "unknown"}`,
        title: result.message?.text?.slice(0, 100) || result.ruleId || "Imported finding",
        description: result.message?.text || "",
        severity: sarifLevelToSeverity(result.level),
        category: "imported",
        confidence: "high",
        location: {
          file: loc?.artifactLocation?.uri || "unknown",
          line: loc?.region?.startLine || 0,
        },
      });
    }
  }
  return findings;
}

function importSemgrep(content: string): Vulnerability[] {
  const data = JSON.parse(content);
  return (data.results || []).map((r: any, i: number) => ({
    id: `IMP-${String(i + 1).padStart(4, "0")}`,
    rule: `imported:${r.check_id}`,
    title: r.check_id?.split(".").pop() || r.check_id,
    description: r.extra?.message || "",
    severity: semgrepSeverity(r.extra?.severity),
    category: "imported",
    confidence: "high" as const,
    location: { file: r.path, line: r.start?.line || 0, snippet: r.extra?.lines?.trim() },
  }));
}

function importSnyk(content: string): Vulnerability[] {
  const data = JSON.parse(content);
  const vulns = data.vulnerabilities || [];
  return vulns.map((v: any, i: number) => ({
    id: `IMP-${String(i + 1).padStart(4, "0")}`,
    rule: `imported:${v.id || "snyk"}`,
    title: v.title || v.id,
    description: v.description || "",
    severity: (v.severity || "medium") as Severity,
    category: "imported",
    cwe: v.identifiers?.CWE?.[0],
    confidence: "high" as const,
    location: { file: v.from?.[0] || "unknown", line: 0 },
  }));
}

function importTrivy(content: string): Vulnerability[] {
  const data = JSON.parse(content);
  const findings: Vulnerability[] = [];
  let id = 1;
  for (const result of data.Results || []) {
    for (const v of result.Vulnerabilities || []) {
      findings.push({
        id: `IMP-${String(id++).padStart(4, "0")}`,
        rule: `imported:${v.VulnerabilityID}`,
        title: `${v.PkgName}@${v.InstalledVersion}: ${v.VulnerabilityID}`,
        description: v.Title || v.Description || "",
        severity: (v.Severity?.toLowerCase() || "medium") as Severity,
        category: "imported",
        cwe: v.VulnerabilityID,
        confidence: "high" as const,
        location: { file: result.Target, line: 0, snippet: `${v.PkgName}@${v.InstalledVersion}` },
      });
    }
  }
  return findings;
}

function sarifLevelToSeverity(level: string): Severity {
  switch (level) {
    case "error": return "high";
    case "warning": return "medium";
    case "note": return "low";
    default: return "medium";
  }
}

function semgrepSeverity(s: string): Severity {
  switch (s?.toUpperCase()) {
    case "ERROR": return "high";
    case "WARNING": return "medium";
    case "INFO": return "low";
    default: return "medium";
  }
}
