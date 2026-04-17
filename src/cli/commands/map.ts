import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import chalk from "chalk";
import ora from "ora";
import { parseCodebase } from "../../analysis/code-parser.js";
import { buildCallGraph } from "../../analysis/call-graph.js";
import { mapEndpoints, assessEndpointSecurity } from "../../analysis/endpoint-mapper.js";
import { mapServices } from "../../analysis/service-mapper.js";
import { loadResults } from "../../store/results-store.js";

interface MapOptions {
  path?: string;
  port: number;
}

export async function mapCommand(options: MapOptions) {
  const projectPath = path.resolve(options.path || ".");

  const spinner = ora("Building attack surface map...").start();

  const codebaseMap = await parseCodebase(projectPath);
  const callGraph = buildCallGraph(codebaseMap, projectPath);
  const endpoints = mapEndpoints(codebaseMap);
  const assessment = assessEndpointSecurity(endpoints);
  const services = await mapServices(projectPath);
  const scanResult = loadResults(projectPath);

  spinner.stop();

  const html = buildMapHtml(codebaseMap, endpoints, assessment, services, scanResult, projectPath);

  const server = http.createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  });

  server.listen(options.port, "127.0.0.1", () => {
    console.log(chalk.bold("\n🗺️  sphinx-agent attack surface map\n"));
    console.log(`  ${chalk.green("➜")} ${chalk.cyan(`http://localhost:${options.port}`)}`);
    console.log(
      chalk.dim(
        `\n  ${endpoints.length} endpoints, ${codebaseMap.functions.length} functions, ${services.services.length} services`
      )
    );
    console.log(chalk.dim("  Press Ctrl+C to stop.\n"));
  });
}

function buildMapHtml(
  codebase: any,
  endpoints: any[],
  assessment: any,
  services: any,
  scanResult: any,
  projectPath: string
): string {
  const vulns = scanResult?.confirmedVulnerabilities || [];
  const projectName = path.basename(projectPath);

  const endpointRows = endpoints
    .map((ep: any) => {
      const vulnCount = vulns.filter((v: any) => v.location.file === ep.file).length;
      return `<tr>
      <td><span class="method ${ep.method.toLowerCase()}">${ep.method}</span></td>
      <td><code>${esc(ep.path)}</code></td>
      <td>${ep.hasAuth ? `<span class="badge ok">${ep.authType || "Yes"}</span>` : '<span class="badge warn">No Auth</span>'}</td>
      <td><span class="badge ${ep.riskLevel}">${ep.riskLevel}</span></td>
      <td>${vulnCount > 0 ? `<span class="badge high">${vulnCount}</span>` : "—"}</td>
      <td><code>${esc(ep.file)}:${ep.line}</code></td>
    </tr>`;
    })
    .join("");

  const serviceNodes = services.services
    .map(
      (s: any) => `{
    id: "${esc(s.name)}",
    label: "${esc(s.name)}",
    type: "${s.type}",
    ports: [${s.ports.join(",")}]
  }`
    )
    .join(",\n    ");

  const serviceEdges = services.connections
    .map(
      (c: any) => `{
    from: "${esc(c.from)}",
    to: "${esc(c.to)}",
    label: "${esc(c.protocol)}"
  }`
    )
    .join(",\n    ");

  const trustBoundaries = services.trustBoundaries
    .map(
      (tb: any) =>
        `<div class="boundary ${tb.exposure}">
      <strong>${esc(tb.name)}</strong> (${tb.exposure})
      <div class="services">${tb.services.map((s: string) => `<span class="chip">${esc(s)}</span>`).join(" ")}</div>
      ${tb.risks.length > 0 ? `<div class="risks">${tb.risks.map((r: string) => `<span class="risk">⚠ ${esc(r)}</span>`).join("<br>")}</div>` : ""}
    </div>`
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Surface Map — ${esc(projectName)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0f; color: #e0e0e0; }
  .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 1.5rem 2rem; border-bottom: 1px solid #1e293b; }
  .header h1 { font-size: 1.4rem; color: #f8fafc; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .stats { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .stat { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 1rem 1.5rem; text-align: center; min-width: 120px; }
  .stat .num { font-size: 2rem; font-weight: 800; }
  .stat .label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; }
  h2 { font-size: 1.1rem; color: #f8fafc; margin: 1.5rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #1e293b; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  th { text-align: left; padding: 0.6rem; font-size: 0.75rem; color: #64748b; text-transform: uppercase; border-bottom: 1px solid #1e293b; }
  td { padding: 0.6rem; border-bottom: 1px solid #111827; font-size: 0.85rem; }
  tr:hover td { background: #111827; }
  code { font-size: 0.8rem; color: #60a5fa; }
  .method { font-weight: 700; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.7rem; }
  .method.get { background: #22c55e22; color: #22c55e; }
  .method.post { background: #3b82f622; color: #3b82f6; }
  .method.put { background: #eab30822; color: #eab308; }
  .method.delete { background: #ef444422; color: #ef4444; }
  .badge { padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.7rem; font-weight: 600; }
  .badge.ok { background: #22c55e22; color: #22c55e; }
  .badge.warn { background: #ef444422; color: #ef4444; }
  .badge.high { background: #ef444422; color: #ef4444; }
  .badge.medium { background: #eab30822; color: #eab308; }
  .badge.low { background: #3b82f622; color: #3b82f6; }
  .boundary { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }
  .boundary.public { border-left: 3px solid #ef4444; }
  .boundary.internal { border-left: 3px solid #eab308; }
  .boundary.private { border-left: 3px solid #22c55e; }
  .chip { display: inline-block; background: #1e293b; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin: 0.25rem 0.15rem; }
  .risks { margin-top: 0.5rem; font-size: 0.8rem; color: #f97316; }
  .services { margin-top: 0.5rem; }
  footer { text-align: center; color: #374151; font-size: 0.75rem; margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #1e293b; }
  footer a { color: #60a5fa; text-decoration: none; }
</style>
</head>
<body>
<div class="header"><h1>🗺️ Attack Surface Map — ${esc(projectName)}</h1></div>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="num" style="color:#60a5fa">${endpoints.length}</div><div class="label">Endpoints</div></div>
    <div class="stat"><div class="num" style="color:#22c55e">${assessment.authenticated}</div><div class="label">Authenticated</div></div>
    <div class="stat"><div class="num" style="color:#ef4444">${assessment.unauthenticated}</div><div class="label">Unauthenticated</div></div>
    <div class="stat"><div class="num" style="color:#f97316">${assessment.highRisk.length}</div><div class="label">High Risk</div></div>
    <div class="stat"><div class="num">${codebase.functions.length}</div><div class="label">Functions</div></div>
    <div class="stat"><div class="num">${services.services.length}</div><div class="label">Services</div></div>
  </div>

  <h2>API Endpoints</h2>
  <table>
    <thead><tr><th>Method</th><th>Path</th><th>Auth</th><th>Risk</th><th>Vulns</th><th>File</th></tr></thead>
    <tbody>${endpointRows}</tbody>
  </table>

  ${services.trustBoundaries.length > 0 ? `<h2>Trust Boundaries</h2>${trustBoundaries}` : ""}

  <footer><p>Generated by <a href="https://github.com/sphinx-agent/sphinx-agent">sphinx-agent</a></p></footer>
</div>
</body>
</html>`;
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
