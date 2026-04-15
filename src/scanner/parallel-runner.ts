import type { SphinxConfig, Vulnerability } from "../types/index.js";
import { PatternScanner } from "./pattern-scanner.js";
import { SecretsScanner } from "./secrets-scanner.js";
import { IacScanner } from "./iac-scanner.js";
import { DepScanner } from "./dep-scanner.js";
import { runAllTools } from "../tools/index.js";

export interface ParallelScanResult {
  findings: Vulnerability[];
  filesScanned: number;
  languages: string[];
  duration: number;
  scanners: {
    name: string;
    findings: number;
    duration: number;
  }[];
}

/**
 * Run all scanners in parallel for maximum speed.
 * Each scanner runs independently and results are merged.
 */
export async function runParallelScan(
  config: SphinxConfig,
  projectPath: string
): Promise<ParallelScanResult> {
  const startTime = Date.now();
  const scannerResults: Array<{
    name: string;
    findings: number;
    duration: number;
  }> = [];

  // Launch all scanners concurrently
  const [patterns, secrets, iac, deps, tools] = await Promise.allSettled([
    // Pattern scanner
    (async () => {
      const start = Date.now();
      const scanner = new PatternScanner(config);
      const result = await scanner.scan(projectPath);
      return {
        name: "patterns",
        findings: result.findings,
        duration: Date.now() - start,
        filesScanned: result.filesScanned,
        languages: result.languages,
      };
    })(),

    // Secrets scanner
    (async () => {
      const start = Date.now();
      const scanner = new SecretsScanner();
      const result = await scanner.scan(projectPath);
      return {
        name: "secrets",
        findings: result.findings,
        duration: Date.now() - start,
      };
    })(),

    // IaC scanner
    (async () => {
      const start = Date.now();
      const scanner = new IacScanner();
      const result = await scanner.scan(projectPath);
      return {
        name: "iac",
        findings: result.findings,
        duration: Date.now() - start,
      };
    })(),

    // Dependency scanner
    (async () => {
      const start = Date.now();
      const scanner = new DepScanner();
      const result = await scanner.scan(projectPath);
      return {
        name: "dependencies",
        findings: result.findings,
        duration: Date.now() - start,
      };
    })(),

    // External tools
    (async () => {
      const start = Date.now();
      const result = await runAllTools(projectPath);
      return {
        name: `tools(${result.toolsRun.join(",") || "none"})`,
        findings: result.findings,
        duration: Date.now() - start,
      };
    })(),
  ]);

  // Collect successful results
  let totalFilesScanned = 0;
  let allLanguages: string[] = [];
  const allFindings: Vulnerability[] = [];

  for (const result of [patterns, secrets, iac, deps, tools]) {
    if (result.status === "fulfilled") {
      const r = result.value;
      allFindings.push(...r.findings);
      scannerResults.push({
        name: r.name,
        findings: r.findings.length,
        duration: r.duration,
      });
      if ("filesScanned" in r && r.filesScanned) totalFilesScanned = r.filesScanned as number;
      if ("languages" in r && r.languages) allLanguages = r.languages as string[];
    }
  }

  return {
    findings: allFindings,
    filesScanned: totalFilesScanned,
    languages: allLanguages,
    duration: Date.now() - startTime,
    scanners: scannerResults,
  };
}
