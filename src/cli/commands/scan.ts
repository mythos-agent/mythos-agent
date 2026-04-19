import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import chalk from "chalk";
import ora, { type Ora } from "ora";
import { loadConfig } from "../../config/config.js";
import { saveResults } from "../../store/results-store.js";
import { AIAnalyzer } from "../../agent/analyzer.js";
import { ChainAnalyzer } from "../../chain/chain-analyzer.js";
import { renderTerminalReport } from "../../report/terminal-reporter.js";
import { renderJsonReport } from "../../report/json-reporter.js";
import { renderSarifReport } from "../../report/sarif-reporter.js";
import { getGitChangedFiles } from "../../scanner/diff-scanner.js";
import { runScan, type PhaseEvent, type PhaseId } from "../../core/run-scan.js";
import type { ScanResult, Severity, Vulnerability } from "../../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgJson = JSON.parse(readFileSync(path.resolve(__dirname, "../../../package.json"), "utf-8"));
const VERSION = pkgJson.version;

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
  headers: boolean;
  jwt: boolean;
  session: boolean;
  bizLogic: boolean;
  crypto: boolean;
  privacy: boolean;
  raceConditions: boolean;
  redos: boolean;
}

// Maps runScan's PhaseId to the CLI's historical "Phase 1x: Label" prefix so
// users who read the terminal output during a scan see the same numbered
// progression they did before the runScan() extraction. Also carries the
// noun used for the finding count summary line ("3 LLM security issues"
// vs "3 API issues"), since each scanner reports a distinct vuln class.
const PHASE_DISPLAY: Record<PhaseId, { prefix: string; label: string; findingNoun: string }> = {
  pattern: { prefix: "Phase 1", label: "Pattern Scan", findingNoun: "potential issues" },
  secrets: { prefix: "Phase 1b", label: "Secrets Detection", findingNoun: "secrets" },
  deps: { prefix: "Phase 1c", label: "Dependency Scan (OSV)", findingNoun: "vulnerable deps" },
  iac: { prefix: "Phase 1d", label: "IaC Security Scan", findingNoun: "misconfigs" },
  llm: { prefix: "Phase 1e", label: "AI/LLM Security Scan", findingNoun: "LLM security issues" },
  "api-sec": { prefix: "Phase 1f", label: "API Security Scan", findingNoun: "API issues" },
  cloud: { prefix: "Phase 1g", label: "Cloud Security Scan", findingNoun: "cloud misconfigs" },
  headers: { prefix: "Phase 1h", label: "Security Headers Scan", findingNoun: "header issues" },
  jwt: { prefix: "Phase 1i", label: "JWT Security Scan", findingNoun: "JWT issues" },
  session: { prefix: "Phase 1j", label: "Session Security Scan", findingNoun: "session issues" },
  "biz-logic": {
    prefix: "Phase 1k",
    label: "Business Logic Scan",
    findingNoun: "biz-logic issues",
  },
  crypto: { prefix: "Phase 1l", label: "Crypto Audit", findingNoun: "crypto issues" },
  privacy: { prefix: "Phase 1m", label: "Privacy/GDPR Scan", findingNoun: "privacy issues" },
  "race-conditions": {
    prefix: "Phase 1n",
    label: "Race Condition Scan",
    findingNoun: "race-condition issues",
  },
  redos: {
    prefix: "Phase 1o",
    label: "ReDoS Scan",
    findingNoun: "ReDoS-vulnerable regex patterns",
  },
  "external-tools": {
    prefix: "Phase 1x",
    label: "External Tools",
    findingNoun: "external-tool findings",
  },
};

// Drives ora spinners off runScan's PhaseEvent stream. Each phase start
// creates a fresh spinner; end/error closes it. Keeping this function in
// scan.ts (rather than run-scan.ts) means runScan stays pure for the
// non-interactive HTTP API caller.
function makeSpinnerReporter(outputFormat: string): (event: PhaseEvent) => void {
  if (outputFormat !== "terminal") return () => {};

  const active = new Map<PhaseId, { spinner: Ora }>();

  return (event: PhaseEvent) => {
    const display = PHASE_DISPLAY[event.id];
    if (!display) return;
    const header = `${display.prefix}: ${display.label}`;

    if (event.state === "start") {
      active.set(event.id, { spinner: ora(header).start() });
      return;
    }

    const entry = active.get(event.id);
    if (!entry) return;
    active.delete(event.id);

    if (event.state === "error") {
      entry.spinner.warn(`${header} — skipped`);
      return;
    }

    const durationStr =
      event.durationMs !== undefined ? chalk.dim(`(${(event.durationMs / 1000).toFixed(1)}s)`) : "";
    const count = event.findings ?? 0;
    const findings =
      count > 0
        ? chalk.red.bold(`${count} ${display.findingNoun}`)
        : event.id === "pattern"
          ? `${count} ${display.findingNoun}`
          : "clean";
    const filesSuffix =
      event.id === "pattern" && event.filesScanned !== undefined
        ? ` in ${event.filesScanned} files`
        : "";
    entry.spinner.succeed(`${header} ${durationStr} — ${findings}${filesSuffix}`.trim());
  };
}

export async function scanCommand(scanPath: string, options: ScanOptions) {
  const projectPath = path.resolve(scanPath);
  const config = loadConfig(projectPath);
  const outputFormat = options.sarif ? "sarif" : options.json ? "json" : options.output;

  // Handle --diff: restrict scan to changed files. Mutates `config` so the
  // same pre-resolved object reaches runScan without a second loadConfig
  // losing the mutation.
  if (options.diff) {
    const base = typeof options.diff === "string" ? options.diff : undefined;
    const changedFiles = getGitChangedFiles(projectPath, base);
    if (changedFiles.length === 0) {
      if (outputFormat === "terminal") {
        console.log(chalk.green("\n✅ No changed files to scan.\n"));
      }
      return;
    }
    config.scan.include = changedFiles.map((f) => f.file);
    config.scan.exclude = [];
  }

  const startTime = Date.now();

  if (outputFormat === "terminal") {
    console.log(chalk.bold(`\n🔐 mythos-agent v${VERSION} — Agentic AI Security Scanner`));
    console.log(chalk.dim("━".repeat(50)));
    console.log(chalk.dim(`\n📁 Scanning: ${projectPath}\n`));
  }

  // Phase 1: delegate the full deterministic-scanner suite to runScan.
  // Before this migration, 15 inline scanner blocks lived here; each new
  // scanner meant three edits (scan.ts, api.ts, KNOWN_EXPERIMENTAL). Now
  // wiring a scanner is one edit in run-scan.ts.
  const runResult = await runScan(projectPath, {
    config,
    secrets: options.secrets,
    deps: options.deps,
    iac: options.iac,
    llm: options.llm,
    apiSec: options.apiSec,
    cloud: options.cloud,
    headers: options.headers,
    jwt: options.jwt,
    session: options.session,
    bizLogic: options.bizLogic,
    crypto: options.crypto,
    privacy: options.privacy,
    raceConditions: options.raceConditions,
    redos: options.redos,
    onPhase: makeSpinnerReporter(outputFormat),
  });

  const { patternFindings, deterministicFindings, filesScanned, languages } = runResult;

  // Phase 2: AI Deep Analysis (CLI-only — requires interactive apiKey).
  // Only pattern findings go through AI verification; deterministic scanners
  // are trusted as-is.
  let phase2Findings: Vulnerability[] = [];
  let confirmed: Vulnerability[] = [...patternFindings, ...deterministicFindings];
  let dismissedCount = 0;

  if (options.ai && config.apiKey) {
    const aiSpinner = outputFormat === "terminal" ? ora("Phase 2: AI Deep Analysis").start() : null;

    try {
      const aiAnalyzer = new AIAnalyzer(config);
      const phase2Start = Date.now();
      const aiResult = await aiAnalyzer.analyze(projectPath, patternFindings);
      const phase2Duration = ((Date.now() - phase2Start) / 1000).toFixed(1);

      phase2Findings = aiResult.discovered;
      dismissedCount = aiResult.dismissedCount;

      confirmed = [...aiResult.confirmed, ...deterministicFindings, ...phase2Findings];

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
            chalk.cyan("mythos-agent init") +
            " to configure."
        )
      );
    }
  }

  // Phase 3: Vulnerability Chaining
  let chains: ScanResult["chains"] = [];

  if (options.chain && confirmed.length >= 2) {
    const chainSpinner =
      outputFormat === "terminal" ? ora("Phase 3: Vulnerability Chaining").start() : null;

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
      console.log(chalk.dim("  ⏭ Phase 3 skipped: need 2+ vulnerabilities to chain"));
    }
  }

  const duration = Date.now() - startTime;

  const result: ScanResult = {
    projectPath,
    timestamp: new Date().toISOString(),
    duration,
    languages,
    filesScanned,
    phase1Findings: patternFindings,
    phase2Findings,
    confirmedVulnerabilities: confirmed,
    dismissedCount,
    chains,
  };

  // Filter by severity threshold
  const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
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
