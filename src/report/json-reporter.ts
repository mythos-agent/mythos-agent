import type { ScanResult } from "../types/index.js";

export function renderJsonReport(result: ScanResult): void {
  const output = {
    version: "0.1.0",
    timestamp: result.timestamp,
    project: result.projectPath,
    duration_ms: result.duration,
    languages: result.languages,
    files_scanned: result.filesScanned,
    summary: {
      total_vulnerabilities: result.confirmedVulnerabilities.length,
      false_positives_dismissed: result.dismissedCount,
      attack_chains: result.chains.length,
      by_severity: {
        critical: result.confirmedVulnerabilities.filter(
          (v) => v.severity === "critical"
        ).length,
        high: result.confirmedVulnerabilities.filter(
          (v) => v.severity === "high"
        ).length,
        medium: result.confirmedVulnerabilities.filter(
          (v) => v.severity === "medium"
        ).length,
        low: result.confirmedVulnerabilities.filter(
          (v) => v.severity === "low"
        ).length,
        info: result.confirmedVulnerabilities.filter(
          (v) => v.severity === "info"
        ).length,
      },
    },
    chains: result.chains.map((chain) => ({
      id: chain.id,
      title: chain.title,
      severity: chain.severity,
      narrative: chain.narrative,
      impact: chain.impact,
      vulnerabilities: chain.vulnerabilities.map((v) => v.id),
    })),
    vulnerabilities: result.confirmedVulnerabilities.map((v) => ({
      id: v.id,
      rule: v.rule,
      title: v.title,
      description: v.description,
      severity: v.severity,
      category: v.category,
      cwe: v.cwe,
      confidence: v.confidence,
      ai_verified: v.aiVerified || false,
      location: {
        file: v.location.file,
        line: v.location.line,
        column: v.location.column,
        snippet: v.location.snippet,
      },
    })),
  };

  console.log(JSON.stringify(output, null, 2));
}
