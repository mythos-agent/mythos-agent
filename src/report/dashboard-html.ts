import path from "node:path";
import type { ScanResult, Vulnerability, VulnChain } from "../types/index.js";

export function buildDashboardHtml(result: ScanResult | null, projectPath: string): string {
  const projectName = path.basename(projectPath);
  const vulns = result?.confirmedVulnerabilities || [];
  const chains = result?.chains || [];

  const counts = {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
  };

  const trustScore = result ? calcTrustScore(vulns, chains) : 10;
  const categories = getCategoryCounts(vulns);
  const timestamp = result?.timestamp ? new Date(result.timestamp).toLocaleString() : "No scan yet";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mythos-agent Dashboard — ${esc(projectName)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e0e0e0; min-height: 100vh; }
  .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 1.5rem 2rem; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 1.4rem; color: #f8fafc; }
  .header h1 span { color: #f43f5e; }
  .header .meta { color: #64748b; font-size: 0.85rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 1.5rem; }
  .card .label { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.08em; }
  .card .value { font-size: 2.5rem; font-weight: 800; margin-top: 0.25rem; }
  .critical-val { color: #ef4444; }
  .high-val { color: #f97316; }
  .medium-val { color: #eab308; }
  .low-val { color: #3b82f6; }
  .good-val { color: #22c55e; }
  .score-ring { width: 120px; height: 120px; margin: 0 auto; position: relative; }
  .score-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .score-ring circle { fill: none; stroke-width: 8; }
  .score-ring .bg { stroke: #1e293b; }
  .score-ring .fg { stroke-linecap: round; transition: stroke-dashoffset 0.5s; }
  .score-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2rem; font-weight: 800; }
  .section { margin-bottom: 2rem; }
  .section h2 { font-size: 1.1rem; color: #f8fafc; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #1e293b; }
  .bar-chart { display: flex; flex-direction: column; gap: 0.5rem; }
  .bar-row { display: flex; align-items: center; gap: 0.75rem; }
  .bar-label { width: 100px; font-size: 0.8rem; color: #94a3b8; text-align: right; }
  .bar-track { flex: 1; height: 24px; background: #1e293b; border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 0.75rem; font-weight: 600; color: #fff; min-width: fit-content; }
  .bar-fill.critical { background: #ef4444; }
  .bar-fill.high { background: #f97316; }
  .bar-fill.medium { background: #eab308; }
  .bar-fill.low { background: #3b82f6; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.75rem; font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #1e293b; }
  td { padding: 0.75rem; border-bottom: 1px solid #111827; font-size: 0.875rem; }
  tr:hover td { background: #111827; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
  .badge-critical { background: #ef444422; color: #ef4444; }
  .badge-high { background: #f9731622; color: #f97316; }
  .badge-medium { background: #eab30822; color: #eab308; }
  .badge-low { background: #3b82f622; color: #3b82f6; }
  .chain-card { background: #1a1020; border: 1px solid #2d1b3d; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }
  .chain-title { font-weight: 600; color: #f8fafc; }
  .chain-steps { margin: 0.5rem 0; padding-left: 1rem; border-left: 2px solid #374151; }
  .chain-step { padding: 0.2rem 0; font-size: 0.85rem; color: #94a3b8; }
  .chain-step code { color: #60a5fa; }
  .chain-narrative { font-size: 0.85rem; color: #9ca3af; font-style: italic; }
  footer { text-align: center; color: #374151; font-size: 0.75rem; margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #1e293b; }
  footer a { color: #60a5fa; text-decoration: none; }
  .refresh-btn { background: #1e293b; color: #94a3b8; border: 1px solid #334155; padding: 0.4rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }
  .refresh-btn:hover { background: #334155; color: #f8fafc; }
</style>
</head>
<body>
<div class="header">
  <h1><span>mythos-agent</span> Dashboard</h1>
  <div>
    <span class="meta">${esc(projectName)} &bull; ${timestamp}</span>
    <button class="refresh-btn" onclick="location.reload()">Refresh</button>
  </div>
</div>
<div class="container">
  <div class="grid">
    <div class="card" style="text-align:center">
      <div class="label">Trust Score</div>
      <div class="score-ring">
        <svg viewBox="0 0 120 120">
          <circle class="bg" cx="60" cy="60" r="52"/>
          <circle class="fg" cx="60" cy="60" r="52"
            stroke="${trustScore >= 7 ? "#22c55e" : trustScore >= 4 ? "#eab308" : "#ef4444"}"
            stroke-dasharray="${2 * Math.PI * 52}"
            stroke-dashoffset="${2 * Math.PI * 52 * (1 - trustScore / 10)}"/>
        </svg>
        <div class="score-text ${trustScore >= 7 ? "good-val" : trustScore >= 4 ? "medium-val" : "critical-val"}">${trustScore.toFixed(1)}</div>
      </div>
    </div>
    <div class="card">
      <div class="label">Critical</div>
      <div class="value critical-val">${counts.critical}</div>
    </div>
    <div class="card">
      <div class="label">High</div>
      <div class="value high-val">${counts.high}</div>
    </div>
    <div class="card">
      <div class="label">Medium</div>
      <div class="value medium-val">${counts.medium}</div>
    </div>
    <div class="card">
      <div class="label">Low</div>
      <div class="value low-val">${counts.low}</div>
    </div>
  </div>

  ${
    categories.length > 0
      ? `
  <div class="section">
    <h2>By Category</h2>
    <div class="bar-chart">
      ${categories
        .map((c) => {
          const maxCount = Math.max(...categories.map((x) => x.count));
          const pct = maxCount > 0 ? (c.count / maxCount) * 100 : 0;
          const sev = c.topSeverity;
          return `<div class="bar-row">
          <div class="bar-label">${esc(c.category)}</div>
          <div class="bar-track">
            <div class="bar-fill ${sev}" style="width:${Math.max(pct, 8)}%">${c.count}</div>
          </div>
        </div>`;
        })
        .join("")}
    </div>
  </div>`
      : ""
  }

  ${
    chains.length > 0
      ? `
  <div class="section">
    <h2>Attack Chains (${chains.length})</h2>
    ${chains
      .map(
        (c) => `
    <div class="chain-card">
      <span class="badge badge-${c.severity}">${c.severity}</span>
      <span class="chain-title">${esc(c.title)}</span>
      <div class="chain-steps">
        ${c.vulnerabilities.map((v) => `<div class="chain-step"><code>${esc(v.location.file)}:${v.location.line}</code> — ${esc(v.title)}</div>`).join("")}
      </div>
      <div class="chain-narrative">${esc(c.narrative)}</div>
    </div>`
      )
      .join("")}
  </div>`
      : ""
  }

  <div class="section">
    <h2>All Findings (${vulns.length})</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Severity</th><th>Title</th><th>File</th><th>Line</th><th>AI</th></tr>
      </thead>
      <tbody>
        ${vulns
          .map(
            (v) => `
        <tr>
          <td style="font-family:monospace;color:#64748b">${v.id}</td>
          <td><span class="badge badge-${v.severity}">${v.severity}</span></td>
          <td>${esc(v.title)}</td>
          <td style="font-family:monospace;color:#60a5fa">${esc(v.location.file)}</td>
          <td>${v.location.line}</td>
          <td>${v.aiVerified ? "✓" : ""}</td>
        </tr>`
          )
          .join("")}
      </tbody>
    </table>
  </div>

  <footer>
    <p>Powered by <a href="https://github.com/mythos-agent/mythos-agent">mythos-agent</a> — Agentic AI Security Scanner</p>
  </footer>
</div>
</body>
</html>`;
}

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function calcTrustScore(vulns: Vulnerability[], chains: VulnChain[]): number {
  let score = 10;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        score -= 2;
        break;
      case "high":
        score -= 1;
        break;
      case "medium":
        score -= 0.5;
        break;
      case "low":
        score -= 0.2;
        break;
    }
  }
  for (const c of chains) {
    switch (c.severity) {
      case "critical":
        score -= 1.5;
        break;
      case "high":
        score -= 1;
        break;
      default:
        score -= 0.5;
    }
  }
  return Math.max(0, Math.min(10, score));
}

function getCategoryCounts(
  vulns: Vulnerability[]
): Array<{ category: string; count: number; topSeverity: string }> {
  const map = new Map<string, { count: number; topSeverity: string }>();
  const order = ["critical", "high", "medium", "low", "info"];
  for (const v of vulns) {
    const existing = map.get(v.category);
    if (existing) {
      existing.count++;
      if (order.indexOf(v.severity) < order.indexOf(existing.topSeverity)) {
        existing.topSeverity = v.severity;
      }
    } else {
      map.set(v.category, { count: 1, topSeverity: v.severity });
    }
  }
  return [...map.entries()]
    .map(([category, data]) => ({ category, ...data }))
    .sort((a, b) => b.count - a.count);
}
