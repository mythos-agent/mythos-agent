import http from "node:http";
import path from "node:path";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";
import { buildDashboardHtml } from "../../report/dashboard-html.js";

interface DashboardOptions {
  port: number;
  path?: string;
}

export async function dashboardCommand(options: DashboardOptions) {
  const projectPath = path.resolve(options.path || ".");
  const port = options.port;

  const server = http.createServer((req, res) => {
    if (req.url === "/api/results") {
      const result = loadResults(projectPath);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result || { error: "No scan results" }));
      return;
    }

    const result = loadResults(projectPath);
    const html = buildDashboardHtml(result, projectPath);
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  });

  server.listen(port, () => {
    console.log(
      chalk.bold("\n📊 sphinx-agent dashboard\n")
    );
    console.log(
      `  ${chalk.green("➜")} Local:   ${chalk.cyan(`http://localhost:${port}`)}`
    );
    console.log(
      chalk.dim(`  Project: ${projectPath}`)
    );
    console.log(
      chalk.dim("\n  Press Ctrl+C to stop.\n")
    );
  });
}
