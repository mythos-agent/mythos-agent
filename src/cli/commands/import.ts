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

  // Open once, stat-and-read on the same fd to close the TOCTOU window
  // between size check and contents read. A swap of the on-disk file after
  // open does not affect the bytes we read here — they come from the inode
  // the fd is bound to.
  const fd = fs.openSync(absPath, "r");
  let content: string;
  try {
    const st = fs.fstatSync(fd);
    if (st.size > 50 * 1024 * 1024) {
      throw new Error(
        `Import file too large (${(st.size / 1024 / 1024).toFixed(1)} MB). Maximum allowed size is 50 MB.`
      );
    }
    const buf = Buffer.alloc(st.size);
    fs.readSync(fd, buf, 0, st.size, 0);
    content = buf.toString("utf-8");
  } finally {
    fs.closeSync(fd);
  }
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

  // Save as mythos-agent results
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
  console.log(
    chalk.green(
      `\n✅ Imported ${findings.length} findings from ${options.format || "auto-detected"} format.\n`
    )
  );
  console.log(
    chalk.dim("  Run mythos-agent report to view, or mythos-agent fix to generate patches.\n")
  );
}

function importSarif(content: string): Vulnerability[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    throw new Error(`Failed to parse SARIF file as JSON: ${(e as Error).message}`);
  }
  const findings: Vulnerability[] = [];
  let id = 1;

  for (const run of (data as any).runs || []) {
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
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    throw new Error(`Failed to parse Semgrep file as JSON: ${(e as Error).message}`);
  }
  return ((data as any).results || []).map((r: any, i: number) => ({
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

const VALID_SEVERITIES: ReadonlySet<string> = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

function importSnyk(content: string): Vulnerability[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    throw new Error(`Failed to parse Snyk file as JSON: ${(e as Error).message}`);
  }
  const vulns = (data as any).vulnerabilities || [];
  return vulns.map((v: any, i: number) => ({
    id: `IMP-${String(i + 1).padStart(4, "0")}`,
    rule: `imported:${v.id || "snyk"}`,
    title: v.title || v.id,
    description: v.description || "",
    severity: (VALID_SEVERITIES.has(v.severity) ? v.severity : "info") as Severity,
    category: "imported",
    cwe: v.identifiers?.CWE?.[0],
    confidence: "high" as const,
    location: { file: v.from?.[0] || "unknown", line: 0 },
  }));
}

function importTrivy(content: string): Vulnerability[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch (e) {
    throw new Error(`Failed to parse Trivy file as JSON: ${(e as Error).message}`);
  }
  const findings: Vulnerability[] = [];
  let id = 1;
  for (const result of (data as any).Results || []) {
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
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    default:
      return "medium";
  }
}

function semgrepSeverity(s: string): Severity {
  switch (s?.toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "low";
    default:
      return "medium";
  }
}
