import path from "node:path";
import fs from "node:fs";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";
import { renderTerminalReport } from "../../report/terminal-reporter.js";
import { renderJsonReport } from "../../report/json-reporter.js";
import { renderHtmlReport } from "../../report/html-reporter.js";
import { renderSarifReport } from "../../report/sarif-reporter.js";
import { saveMarkdownReport } from "../../report/markdown-reporter.js";

interface ReportOptions {
  output: string;
  json?: boolean;
  html?: boolean;
  sarif?: boolean;
  md?: boolean;
  path?: string;
}

export async function reportCommand(options: ReportOptions) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(
      chalk.yellow(
        "\n⚠️  No scan results found. Run " + chalk.cyan("mythos-agent scan") + " first.\n"
      )
    );
    return;
  }

  const format = options.md
    ? "md"
    : options.sarif
      ? "sarif"
      : options.html
        ? "html"
        : options.json
          ? "json"
          : options.output;

  switch (format) {
    case "json":
      renderJsonReport(result);
      break;
    case "html": {
      const outputPath = renderHtmlReport(result, projectPath);
      console.log(chalk.green(`\n✅ HTML report saved to ${outputPath}\n`));
      break;
    }
    case "sarif": {
      const sarifOutput = renderSarifReport(result);
      const sarifPath = path.join(projectPath, ".sphinx", "results.sarif");
      fs.mkdirSync(path.dirname(sarifPath), { recursive: true });
      fs.writeFileSync(sarifPath, sarifOutput, "utf-8");
      console.log(chalk.green(`\n✅ SARIF report saved to ${sarifPath}\n`));
      break;
    }
    case "md": {
      const mdPath = saveMarkdownReport(result, projectPath);
      console.log(chalk.green(`\n✅ Markdown report saved to ${mdPath}\n`));
      break;
    }
    default:
      renderTerminalReport(result);
  }
}
