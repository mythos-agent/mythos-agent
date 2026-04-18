import fs from "node:fs";
import path from "node:path";
import type { ScanResult, Vulnerability, VulnChain, Severity } from "../types/index.js";

export function renderHtmlReport(result: ScanResult, projectPath: string): string {
  const html = buildHtml(result);
  const outputDir = path.join(projectPath, ".sphinx");
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  const outputPath = path.join(outputDir, "report.html");
  fs.writeFileSync(outputPath, html, "utf-8");
  return outputPath;
}

function buildHtml(result: ScanResult): string {
  const { confirmedVulnerabilities: vulns, chains } = result;
  const duration = (result.duration / 1000).toFixed(1);

  const counts = {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
  };

  const trustScore = calculateTrustScore(vulns, chains);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mythos-agent Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 2rem; }
  header { text-align: center; margin-bottom: 3rem; padding-bottom: 2rem; border-bottom: 1px solid #21262d; }
  header h1 { font-size: 2rem; color: #f0f6fc; margin-bottom: 0.5rem; }
  header p { color: #8b949e; }
  .meta { display: flex; gap: 2rem; justify-content: center; margin-top: 1rem; color: #8b949e; font-size: 0.875rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .summary-card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1.25rem; text-align: center; }
  .summary-card .number { font-size: 2rem; font-weight: 700; }
  .summary-card .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
  .critical { color: #f85149; }
  .high { color: #f0883e; }
  .medium { color: #d29922; }
  .low { color: #58a6ff; }
  .good { color: #3fb950; }
  .trust-score { font-size: 3rem; font-weight: 800; }
  section { margin-bottom: 2.5rem; }
  section h2 { font-size: 1.25rem; color: #f0f6fc; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #21262d; }
  .chain { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
  .chain-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
  .badge-critical { background: #f8514922; color: #f85149; border: 1px solid #f8514944; }
  .badge-high { background: #f0883e22; color: #f0883e; border: 1px solid #f0883e44; }
  .badge-medium { background: #d2992222; color: #d29922; border: 1px solid #d2992244; }
  .badge-low { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; }
  .chain-steps { margin: 0.75rem 0; padding-left: 1.25rem; border-left: 2px solid #30363d; }
  .chain-step { padding: 0.25rem 0; font-size: 0.875rem; }
  .chain-step code { color: #58a6ff; font-size: 0.8rem; }
  .chain-narrative { color: #8b949e; font-style: italic; margin-top: 0.5rem; font-size: 0.875rem; }
  .chain-impact { color: #f0883e; font-size: 0.875rem; margin-top: 0.25rem; }
  .vuln { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 0.75rem; }
  .vuln-header { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
  .vuln-id { color: #8b949e; font-family: monospace; font-size: 0.8rem; }
  .vuln-title { font-weight: 600; color: #f0f6fc; }
  .vuln-verified { font-size: 0.7rem; color: #3fb950; background: #3fb95022; padding: 0.1rem 0.4rem; border-radius: 3px; }
  .vuln-location { font-family: monospace; font-size: 0.8rem; color: #58a6ff; margin-top: 0.4rem; }
  .vuln-snippet { font-family: monospace; font-size: 0.8rem; color: #8b949e; background: #0d1117; padding: 0.5rem; border-radius: 4px; margin-top: 0.4rem; overflow-x: auto; }
  .vuln-cwe { color: #8b949e; font-size: 0.75rem; }
  footer { text-align: center; color: #484f58; font-size: 0.8rem; margin-top: 3rem; padding-top: 2rem; border-top: 1px solid #21262d; }
  footer a { color: #58a6ff; text-decoration: none; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>mythos-agent Security Report</h1>
    <p>Agentic AI Security Scanner</p>
    <div class="meta">
      <span>Project: ${escapeHtml(path.basename(result.projectPath))}</span>
      <span>Scanned: ${new Date(result.timestamp).toLocaleString()}</span>
      <span>Duration: ${duration}s</span>
      <span>Files: ${result.filesScanned}</span>
    </div>
  </header>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="number trust-score ${trustScore >= 8 ? "good" : trustScore >= 5 ? "medium" : "critical"}">${trustScore.toFixed(1)}</div>
      <div class="label">Trust Score</div>
    </div>
    <div class="summary-card">
      <div class="number critical">${counts.critical}</div>
      <div class="label">Critical</div>
    </div>
    <div class="summary-card">
      <div class="number high">${counts.high}</div>
      <div class="label">High</div>
    </div>
    <div class="summary-card">
      <div class="number medium">${counts.medium}</div>
      <div class="label">Medium</div>
    </div>
    <div class="summary-card">
      <div class="number low">${counts.low}</div>
      <div class="label">Low</div>
    </div>
    <div class="summary-card">
      <div class="number good">${result.dismissedCount}</div>
      <div class="label">Dismissed</div>
    </div>
  </div>

  ${chains.length > 0 ? renderChainsHtml(chains) : ""}

  <section>
    <h2>Vulnerabilities (${vulns.length})</h2>
    ${vulns.map(renderVulnHtml).join("\n")}
  </section>

  <footer>
    <p>Generated by <a href="https://github.com/mythos-agent/mythos-agent">mythos-agent</a> — Agentic AI Security Scanner</p>
    <p style="margin-top: 0.25rem">Mythos for everyone.</p>
  </footer>
</div>
</body>
</html>`;
}

function renderChainsHtml(chains: VulnChain[]): string {
  return `<section>
    <h2>Attack Chains (${chains.length})</h2>
    ${chains
      .map(
        (chain) => `
    <div class="chain">
      <div class="chain-header">
        <span class="badge badge-${chain.severity}">${chain.severity}</span>
        <strong>${escapeHtml(chain.title)}</strong>
      </div>
      <div class="chain-steps">
        ${chain.vulnerabilities
          .map(
            (v) => `
        <div class="chain-step">
          <code>${escapeHtml(v.location.file)}:${v.location.line}</code>
          <span style="color: #8b949e;"> — ${escapeHtml(v.title)}</span>
        </div>`
          )
          .join("")}
      </div>
      <div class="chain-narrative">${escapeHtml(chain.narrative)}</div>
      <div class="chain-impact">Impact: ${escapeHtml(chain.impact)}</div>
    </div>`
      )
      .join("\n")}
  </section>`;
}

function renderVulnHtml(vuln: Vulnerability): string {
  return `<div class="vuln">
      <div class="vuln-header">
        <span class="badge badge-${vuln.severity}">${vuln.severity}</span>
        <span class="vuln-id">${vuln.id}</span>
        <span class="vuln-title">${escapeHtml(vuln.title)}</span>
        ${vuln.aiVerified ? '<span class="vuln-verified">AI Verified</span>' : ""}
        ${vuln.cwe ? `<span class="vuln-cwe">${vuln.cwe}</span>` : ""}
      </div>
      <div class="vuln-location">${escapeHtml(vuln.location.file)}:${vuln.location.line}</div>
      ${vuln.location.snippet ? `<div class="vuln-snippet">${escapeHtml(vuln.location.snippet)}</div>` : ""}
    </div>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function calculateTrustScore(vulns: Vulnerability[], chains: VulnChain[]): number {
  let score = 10;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        score -= 2.0;
        break;
      case "high":
        score -= 1.0;
        break;
      case "medium":
        score -= 0.5;
        break;
      case "low":
        score -= 0.2;
        break;
    }
  }
  for (const chain of chains) {
    switch (chain.severity) {
      case "critical":
        score -= 1.5;
        break;
      case "high":
        score -= 1.0;
        break;
      default:
        score -= 0.5;
    }
  }
  return Math.max(0, Math.min(10, score));
}
