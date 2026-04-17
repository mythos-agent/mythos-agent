import path from "node:path";
import chalk from "chalk";
import { createServer } from "../../server/api.js";

interface ServeOptions {
  port: number;
  host: string;
  path?: string;
  apiKey?: string;
}

export async function serveCommand(options: ServeOptions) {
  const projectPath = path.resolve(options.path || ".");

  const server = createServer({
    port: options.port,
    host: options.host,
    projectPath,
    apiKey: options.apiKey,
  });

  server.listen(options.port, options.host, () => {
    console.log(chalk.bold("\n🔐 sphinx-agent API server\n"));
    console.log(`  ${chalk.green("➜")} ${chalk.cyan(`http://${options.host}:${options.port}`)}`);
    console.log(chalk.dim(`  Project: ${projectPath}`));
    console.log(
      chalk.dim(`  Auth: ${options.apiKey ? "Bearer token required" : "open (no auth)"}`)
    );
    console.log(chalk.dim("\n  Endpoints:"));
    console.log(chalk.dim("    GET  /api/health        — server health check"));
    console.log(chalk.dim("    GET  /api/results        — latest scan results"));
    console.log(chalk.dim("    GET  /api/results/sarif   — SARIF format"));
    console.log(chalk.dim("    GET  /api/results/markdown — Markdown report"));
    console.log(chalk.dim("    GET  /api/baseline       — baseline comparison"));
    console.log(chalk.dim("    GET  /api/policy         — policy check"));
    console.log(chalk.dim("    GET  /api/history        — scan history"));
    console.log(chalk.dim("    POST /api/scan           — trigger new scan"));
    console.log(chalk.dim("\n  Press Ctrl+C to stop.\n"));
  });
}
