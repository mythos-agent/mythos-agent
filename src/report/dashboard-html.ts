import path from "node:path";
import type { ScanResult, Vulnerability, VulnChain } from "../types/index.js";
import { BRAND, SEVERITY_HEX } from "./brand.js";

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
  :root {
    --bg: ${BRAND.nearBlack};
    --surface: ${BRAND.surface};
    --surface-raised: ${BRAND.surfaceRaised};
    --border: ${BRAND.border};
    --border-strong: ${BRAND.borderStrong};
    --text: ${BRAND.offWhite};
    --muted: ${BRAND.muted};
    --subtle: ${BRAND.subtle};
    --brand: ${BRAND.violet};
    --code: ${BRAND.cyan};
    --critical: ${SEVERITY_HEX.critical};
    --high: ${SEVERITY_HEX.high};
    --medium: ${SEVERITY_HEX.medium};
    --low: ${SEVERITY_HEX.low};
    --good: ${SEVERITY_HEX.verified};
    --mono: "Geist Mono", ui-monospace, SFMono-Regular, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  .header { background: var(--surface); padding: 1.5rem 2rem; border-bottom: 2px solid var(--brand); display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 1.4rem; color: var(--text); }
  .header h1 span { color: var(--brand); }
  .header .meta { color: var(--muted); font-size: 0.85rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }
  .card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }
  .card .value { font-size: 2.5rem; font-weight: 800; margin-top: 0.25rem; }
  .critical-val { color: var(--critical); }
  .high-val { color: var(--high); }
  .medium-val { color: var(--medium); }
  .low-val { color: var(--low); }
  .good-val { color: var(--good); }
  .score-ring { width: 120px; height: 120px; margin: 0 auto; position: relative; }
  .score-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .score-ring circle { fill: none; stroke-width: 8; }
  .score-ring .bg { stroke: var(--border); }
  .score-ring .fg { stroke-linecap: round; transition: stroke-dashoffset 0.5s; }
  .score-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2rem; font-weight: 800; }
  .section { margin-bottom: 2rem; }
  .section h2 { font-size: 1.1rem; color: var(--text); margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
  .bar-chart { display: flex; flex-direction: column; gap: 0.5rem; }
  .bar-row { display: flex; align-items: center; gap: 0.75rem; }
  .bar-label { width: 100px; font-size: 0.8rem; color: var(--muted); text-align: right; }
  .bar-track { flex: 1; height: 24px; background: var(--surface-raised); border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 0.75rem; font-weight: 600; color: var(--bg); min-width: fit-content; }
  .bar-fill.critical { background: var(--critical); color: var(--text); }
  .bar-fill.high { background: var(--high); }
  .bar-fill.medium { background: var(--medium); }
  .bar-fill.low { background: var(--low); color: var(--bg); }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.75rem; font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
  td { padding: 0.75rem; border-bottom: 1px solid var(--surface); font-size: 0.875rem; }
  tr:hover td { background: var(--surface); }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
  .badge-critical { background: ${SEVERITY_HEX.critical}22; color: var(--critical); }
  .badge-high { background: ${SEVERITY_HEX.high}22; color: var(--high); }
  .badge-medium { background: ${SEVERITY_HEX.medium}22; color: var(--medium); }
  .badge-low { background: ${SEVERITY_HEX.low}22; color: var(--low); }
  .chain-card { background: var(--surface); border: 1px solid var(--brand); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }
  .chain-title { font-weight: 600; color: var(--text); }
  .chain-steps { margin: 0.5rem 0; padding-left: 1rem; border-left: 2px solid var(--border); }
  .chain-step { padding: 0.2rem 0; font-size: 0.85rem; color: var(--muted); font-family: var(--mono); }
  .chain-step code { color: var(--code); font-family: var(--mono); }
  .chain-narrative { font-size: 0.85rem; color: var(--muted); font-style: italic; }
  footer { text-align: center; color: var(--muted); font-size: 0.75rem; margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }
  footer a { color: var(--code); text-decoration: none; }
  .refresh-btn { background: var(--surface); color: var(--muted); border: 1px solid var(--border-strong); padding: 0.4rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }
  .refresh-btn:hover { background: var(--surface-raised); color: var(--text); }
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
            stroke="${trustScore >= 7 ? SEVERITY_HEX.verified : trustScore >= 4 ? SEVERITY_HEX.medium : SEVERITY_HEX.critical}"
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
          <td style="font-family:var(--mono);color:var(--muted)">${v.id}</td>
          <td><span class="badge badge-${v.severity}">${v.severity}</span></td>
          <td>${esc(v.title)}</td>
          <td style="font-family:var(--mono);color:var(--code)">${esc(v.location.file)}</td>
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
