import path from "node:path";
import chalk from "chalk";
import { loadConfig } from "../../config/config.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import { IacScanner } from "../../scanner/iac-scanner.js";
import { LlmSecurityScanner } from "../../scanner/llm-security-scanner.js";
import { ApiSecurityScanner } from "../../scanner/api-security-scanner.js";
import { CloudSecurityScanner } from "../../scanner/cloud-scanner.js";
import { CryptoScanner } from "../../scanner/crypto-scanner.js";
import { PrivacyScanner } from "../../scanner/privacy-scanner.js";

interface BenchmarkOptions {
  path?: string;
  json?: boolean;
}

interface ScannerBench {
  name: string;
  duration: number;
  findings: number;
  filesScanned: number;
}

export async function benchmarkCommand(options: BenchmarkOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);

  if (!options.json) {
    console.log(chalk.bold("\n⏱️  mythos-agent benchmark\n"));
    console.log(chalk.dim(`  Project: ${projectPath}\n`));
  }

  const results: ScannerBench[] = [];
  const totalStart = Date.now();

  const scanners: Array<{
    name: string;
    run: () => Promise<{ findings: { length: number }; filesScanned?: number }>;
  }> = [
    {
      name: "patterns",
      run: async () => {
        const s = new PatternScanner(config);
        return s.scan(projectPath, false);
      },
    },
    { name: "secrets", run: async () => new SecretsScanner().scan(projectPath) },
    { name: "iac", run: async () => new IacScanner().scan(projectPath) },
    { name: "llm-security", run: async () => new LlmSecurityScanner().scan(projectPath) },
    { name: "api-security", run: async () => new ApiSecurityScanner().scan(projectPath) },
    { name: "cloud", run: async () => new CloudSecurityScanner().scan(projectPath) },
    { name: "crypto", run: async () => new CryptoScanner().scan(projectPath) },
    { name: "privacy", run: async () => new PrivacyScanner().scan(projectPath) },
  ];

  for (const scanner of scanners) {
    const start = Date.now();
    try {
      const result = await scanner.run();
      const duration = Date.now() - start;
      results.push({
        name: scanner.name,
        duration,
        findings: result.findings.length,
        filesScanned: (result as any).filesScanned || 0,
      });
    } catch {
      results.push({
        name: scanner.name,
        duration: Date.now() - start,
        findings: 0,
        filesScanned: 0,
      });
    }
  }

  const totalDuration = Date.now() - totalStart;
  const totalFindings = results.reduce((s, r) => s + r.findings, 0);

  if (options.json) {
    console.log(JSON.stringify({ totalDuration, totalFindings, scanners: results }, null, 2));
    return;
  }

  // Render benchmark table
  const maxName = Math.max(...results.map((r) => r.name.length));

  console.log(
    chalk.dim(`  ${"Scanner".padEnd(maxName + 2)} ${"Time".padStart(8)} ${"Findings".padStart(10)}`)
  );
  console.log(chalk.dim("  " + "─".repeat(maxName + 24)));

  for (const r of results.sort((a, b) => b.duration - a.duration)) {
    const bar = "█".repeat(Math.max(1, Math.round((r.duration / totalDuration) * 30)));
    const timeColor = r.duration > 1000 ? chalk.yellow : chalk.green;
    console.log(
      `  ${r.name.padEnd(maxName + 2)} ${timeColor(`${r.duration}ms`.padStart(8))} ${String(r.findings).padStart(10)}  ${chalk.dim(bar)}`
    );
  }

  console.log(chalk.dim("  " + "─".repeat(maxName + 24)));
  console.log(
    chalk.bold(
      `  ${"TOTAL".padEnd(maxName + 2)} ${`${totalDuration}ms`.padStart(8)} ${String(totalFindings).padStart(10)}`
    )
  );

  // Performance grade
  const grade =
    totalDuration < 500 ? "A" : totalDuration < 2000 ? "B" : totalDuration < 5000 ? "C" : "D";
  const gradeColor =
    grade === "A"
      ? chalk.green
      : grade === "B"
        ? chalk.green
        : grade === "C"
          ? chalk.yellow
          : chalk.red;
  console.log(
    chalk.bold(`\n  Performance: ${gradeColor(grade)} (${(totalDuration / 1000).toFixed(2)}s)\n`)
  );
}
