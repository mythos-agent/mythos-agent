import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import chalk from "chalk";
import ora from "ora";
import { loadConfig } from "../../config/config.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgJson = JSON.parse(
  readFileSync(path.resolve(__dirname, "../../../package.json"), "utf-8")
);
const VERSION = pkgJson.version;
import { saveResults } from "../../store/results-store.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { AIAnalyzer } from "../../agent/analyzer.js";
import { ChainAnalyzer } from "../../chain/chain-analyzer.js";
import { renderTerminalReport } from "../../report/terminal-reporter.js";
import { renderJsonReport } from "../../report/json-reporter.js";
import { renderSarifReport } from "../../report/sarif-reporter.js";
import { getGitChangedFiles } from "../../scanner/diff-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import { DepScanner } from "../../scanner/dep-scanner.js";
import { IacScanner } from "../../scanner/iac-scanner.js";
import { LlmSecurityScanner } from "../../scanner/llm-security-scanner.js";
import { ApiSecurityScanner } from "../../scanner/api-security-scanner.js";
import { CloudSecurityScanner } from "../../scanner/cloud-scanner.js";
import type { ScanResult, Severity, Vulnerability } from "../../types/index.js";

interface ScanOptions {
  ai: boolean;
  chain: boolean;
  severity: Severity;
  output: string;
  json?: boolean;
  sarif?: boolean;
  diff?: string | boolean;
  rules?: string;
  secrets: boolean;
  deps: boolean;
  iac: boolean;
  llm: boolean;
  apiSec: boolean;
  cloud: boolean;
}

export async function scanCommand(scanPath: string, options: ScanOptions) {
  const projectPath = path.resolve(scanPath);
  const config = loadConfig(projectPath);
  const outputFormat = options.sarif ? "sarif" : options.json ? "json" : options.output;

  // Handle --diff: restrict scan to changed files
  if (options.diff) {
    const base = typeof options.diff === "string" ? options.diff : undefined;
    const changedFiles = getGitChangedFiles(projectPath, base);
    if (changedFiles.length === 0) {
      if (outputFormat === "terminal") {
        console.log(chalk.green("\n✅ No changed files to scan.\n"));
      }
      return;
    }
    // Override include patterns to only scan changed files
    config.scan.include = changedFiles.map((f) => f.file);
    config.scan.exclude = [];
  }

  const startTime = Date.now();

  if (outputFormat === "terminal") {
    console.log(
      chalk.bold(`\n🔐 sphinx-agent v${VERSION} — Agentic AI Security Scanner`)
    );
    console.log(chalk.dim("━".repeat(50)));
    console.log(chalk.dim(`\n📁 Scanning: ${projectPath}\n`));
  }

  // Phase 1: Pattern Scan
  const spinner =
    outputFormat === "terminal"
      ? ora("Phase 1: Pattern Scan").start()
      : null;

  const patternScanner = new PatternScanner(config);
  const phase1Start = Date.now();
  const { findings: phase1Findings, filesScanned, languages } =
    await patternScanner.scan(projectPath);
  const phase1Duration = ((Date.now() - phase1Start) / 1000).toFixed(1);

  if (spinner) {
    spinner.succeed(
      `Phase 1: Pattern Scan ${chalk.dim(`(${phase1Duration}s)`)} — ${phase1Findings.length} potential issues in ${filesScanned} files`
    );
  }

  // Phase 1b: Secrets Detection
  let secretsFindings: Vulnerability[] = [];
  if (options.secrets) {
    const secretsSpinner =
      outputFormat === "terminal"
        ? ora("Phase 1b: Secrets Detection").start()
        : null;

    const secretsScanner = new SecretsScanner();
    const secretsStart = Date.now();
    const secretsResult = await secretsScanner.scan(projectPath);
    const secretsDuration = ((Date.now() - secretsStart) / 1000).toFixed(1);
    secretsFindings = secretsResult.findings;

    if (secretsSpinner) {
      if (secretsFindings.length > 0) {
        secretsSpinner.succeed(
          `Phase 1b: Secrets Detection ${chalk.dim(`(${secretsDuration}s)`)} — ${chalk.red.bold(`${secretsFindings.length} secrets found`)} in ${secretsResult.filesScanned} files`
        );
      } else {
        secretsSpinner.succeed(
          `Phase 1b: Secrets Detection ${chalk.dim(`(${secretsDuration}s)`)} — no secrets found`
        );
      }
    }
  }

  // Phase 1c: Dependency Scanning
  let depFindings: Vulnerability[] = [];
  if (options.deps) {
    const depSpinner =
      outputFormat === "terminal"
        ? ora("Phase 1c: Dependency Scan (OSV)").start()
        : null;

    try {
      const depScanner = new DepScanner();
      const depStart = Date.now();
      const depResult = await depScanner.scan(projectPath);
      const depDuration = ((Date.now() - depStart) / 1000).toFixed(1);
      depFindings = depResult.findings;

      if (depSpinner) {
        if (depFindings.length > 0) {
          depSpinner.succeed(
            `Phase 1c: Dependency Scan ${chalk.dim(`(${depDuration}s)`)} — ${chalk.red.bold(`${depFindings.length} vulnerable deps`)} in ${depResult.totalDependencies} packages`
          );
        } else {
          depSpinner.succeed(
            `Phase 1c: Dependency Scan ${chalk.dim(`(${depDuration}s)`)} — ${depResult.totalDependencies} packages clean`
          );
        }
      }
    } catch (err) {
      if (depSpinner) {
        depSpinner.warn(
          `Phase 1c: Dependency Scan — skipped (${err instanceof Error ? err.message : "error"})`
        );
      }
    }
  }

  // Phase 1d: IaC Scanning
  let iacFindings: Vulnerability[] = [];
  if (options.iac) {
    const iacSpinner =
      outputFormat === "terminal"
        ? ora("Phase 1d: IaC Security Scan").start()
        : null;

    try {
      const iacScanner = new IacScanner();
      const iacStart = Date.now();
      const iacResult = await iacScanner.scan(projectPath);
      const iacDuration = ((Date.now() - iacStart) / 1000).toFixed(1);
      iacFindings = iacResult.findings;

      if (iacSpinner) {
        if (iacFindings.length > 0) {
          iacSpinner.succeed(
            `Phase 1d: IaC Security Scan ${chalk.dim(`(${iacDuration}s)`)} — ${chalk.red.bold(`${iacFindings.length} misconfigs`)} in ${iacResult.filesScanned} files`
          );
        } else if (iacResult.filesScanned > 0) {
          iacSpinner.succeed(
            `Phase 1d: IaC Security Scan ${chalk.dim(`(${iacDuration}s)`)} — ${iacResult.filesScanned} IaC files clean`
          );
        } else {
          iacSpinner.succeed(
            `Phase 1d: IaC Security Scan ${chalk.dim(`(${iacDuration}s)`)} — no IaC files found`
          );
        }
      }
    } catch (err) {
      if (iacSpinner) {
        iacSpinner.warn(
          `Phase 1d: IaC Security Scan — skipped (${err instanceof Error ? err.message : "error"})`
        );
      }
    }
  }

  // Phase 1e: AI/LLM Security Scan
  let llmFindings: Vulnerability[] = [];
  if (options.llm) {
    const llmSpinner = outputFormat === "terminal" ? ora("Phase 1e: AI/LLM Security Scan").start() : null;
    try {
      const llmScanner = new LlmSecurityScanner();
      const llmResult = await llmScanner.scan(projectPath);
      llmFindings = llmResult.findings;
      if (llmSpinner) {
        llmSpinner.succeed(
          `Phase 1e: AI/LLM Security ${chalk.dim(`—`)} ${llmFindings.length > 0 ? chalk.red.bold(`${llmFindings.length} LLM security issues`) : "clean"}`
        );
      }
    } catch (err) {
      if (llmSpinner) llmSpinner.warn(`Phase 1e: AI/LLM Security — skipped`);
    }
  }

  // Phase 1f: API Security Scan
  let apiSecFindings: Vulnerability[] = [];
  if (options.apiSec) {
    const apiSpinner = outputFormat === "terminal" ? ora("Phase 1f: API Security Scan").start() : null;
    try {
      const apiScanner = new ApiSecurityScanner();
      const apiResult = await apiScanner.scan(projectPath);
      apiSecFindings = apiResult.findings;
      if (apiSpinner) {
        apiSpinner.succeed(
          `Phase 1f: API Security ${chalk.dim(`—`)} ${apiSecFindings.length > 0 ? chalk.red.bold(`${apiSecFindings.length} API issues`) : "clean"}`
        );
      }
    } catch (err) {
      if (apiSpinner) apiSpinner.warn(`Phase 1f: API Security — skipped`);
    }
  }

  // Phase 1g: Cloud Misconfiguration Scan
  let cloudFindings: Vulnerability[] = [];
  if (options.cloud) {
    const cloudSpinner = outputFormat === "terminal" ? ora("Phase 1g: Cloud Security Scan").start() : null;
    try {
      const cloudScanner = new CloudSecurityScanner();
      const cloudResult = await cloudScanner.scan(projectPath);
      cloudFindings = cloudResult.findings;
      if (cloudSpinner) {
        cloudSpinner.succeed(
          `Phase 1g: Cloud Security ${chalk.dim(`—`)} ${cloudFindings.length > 0 ? chalk.red.bold(`${cloudFindings.length} cloud misconfigs`) : "clean"}`
        );
      }
    } catch (err) {
      if (cloudSpinner) cloudSpinner.warn(`Phase 1g: Cloud Security — skipped`);
    }
  }

  // Phase 2: AI Deep Analysis
  let phase2Findings: Vulnerability[] = [];
  let confirmed: Vulnerability[] = [
    ...phase1Findings, ...secretsFindings, ...depFindings, ...iacFindings,
    ...llmFindings, ...apiSecFindings, ...cloudFindings,
  ];
  let dismissedCount = 0;

  if (options.ai && config.apiKey) {
    const aiSpinner =
      outputFormat === "terminal"
        ? ora("Phase 2: AI Deep Analysis").start()
        : null;

    try {
      const aiAnalyzer = new AIAnalyzer(config);
      const phase2Start = Date.now();
      const aiResult = await aiAnalyzer.analyze(
        projectPath,
        phase1Findings
      );
      const phase2Duration = ((Date.now() - phase2Start) / 1000).toFixed(1);

      phase2Findings = aiResult.discovered;
      dismissedCount = aiResult.dismissedCount;

      // AI only verifies phase1 findings — preserve secrets/dep/IaC findings
      confirmed = [
        ...aiResult.confirmed,
        ...secretsFindings,
        ...depFindings,
        ...iacFindings,
        ...phase2Findings,
      ];

      if (aiSpinner) {
        aiSpinner.succeed(
          `Phase 2: AI Deep Analysis ${chalk.dim(`(${phase2Duration}s)`)} — confirmed ${confirmed.length - phase2Findings.length}, discovered ${phase2Findings.length} new, dismissed ${dismissedCount}`
        );
      }
    } catch (err) {
      if (aiSpinner) {
        aiSpinner.warn(
          `Phase 2: AI Deep Analysis — skipped (${err instanceof Error ? err.message : "error"})`
        );
      }
    }
  } else if (options.ai && !config.apiKey) {
    if (outputFormat === "terminal") {
      console.log(
        chalk.yellow(
          "  ⚠ Phase 2 skipped: no API key. Run " +
            chalk.cyan("sphinx-agent init") +
            " to configure."
        )
      );
    }
  }

  // Phase 3: Vulnerability Chaining
  let chains: ScanResult["chains"] = [];

  if (options.chain && confirmed.length >= 2) {
    const chainSpinner =
      outputFormat === "terminal"
        ? ora("Phase 3: Vulnerability Chaining").start()
        : null;

    try {
      const chainAnalyzer = new ChainAnalyzer(config);
      const phase3Start = Date.now();
      chains = await chainAnalyzer.analyzeChains(confirmed, projectPath);
      const phase3Duration = ((Date.now() - phase3Start) / 1000).toFixed(1);

      if (chainSpinner) {
        if (chains.length > 0) {
          chainSpinner.succeed(
            `Phase 3: Vulnerability Chaining ${chalk.dim(`(${phase3Duration}s)`)} — found ${chains.length} exploitable chain${chains.length > 1 ? "s" : ""}`
          );
        } else {
          chainSpinner.succeed(
            `Phase 3: Vulnerability Chaining ${chalk.dim(`(${phase3Duration}s)`)} — no chains found`
          );
        }
      }
    } catch (err) {
      if (chainSpinner) {
        chainSpinner.warn(
          `Phase 3: Vulnerability Chaining — skipped (${err instanceof Error ? err.message : "error"})`
        );
      }
    }
  } else if (options.chain && confirmed.length < 2) {
    if (outputFormat === "terminal") {
      console.log(
        chalk.dim("  ⏭ Phase 3 skipped: need 2+ vulnerabilities to chain")
      );
    }
  }

  const duration = Date.now() - startTime;

  const result: ScanResult = {
    projectPath,
    timestamp: new Date().toISOString(),
    duration,
    languages,
    filesScanned,
    phase1Findings,
    phase2Findings,
    confirmedVulnerabilities: confirmed,
    dismissedCount,
    chains,
  };

  // Filter by severity threshold
  const severityOrder: Severity[] = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ];
  const thresholdIdx = severityOrder.indexOf(options.severity);
  result.confirmedVulnerabilities = result.confirmedVulnerabilities.filter(
    (v) => severityOrder.indexOf(v.severity) <= thresholdIdx
  );

  // Save results for fix/report commands
  saveResults(projectPath, result);

  // Output
  switch (outputFormat) {
    case "json":
      renderJsonReport(result);
      break;
    case "sarif":
      console.log(renderSarifReport(result));
      break;
    default:
      renderTerminalReport(result);
  }
}
