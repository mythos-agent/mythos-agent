import path from "node:path";
import chalk from "chalk";
import { loadConfig } from "../../config/config.js";
import { Orchestrator } from "../../agents/orchestrator.js";
import { saveResults } from "../../store/results-store.js";
import { renderTerminalReport } from "../../report/terminal-reporter.js";
import type { ScanResult } from "../../types/index.js";

interface HuntOptions {
  json?: boolean;
}

export async function huntCommand(huntPath: string, options: HuntOptions) {
  const projectPath = path.resolve(huntPath);
  const config = loadConfig(projectPath);

  console.log(
    chalk.bold(
      "\n🔐 sphinx-agent hunt — Autonomous Security Agent\n"
    )
  );
  console.log(chalk.dim("━".repeat(50)));
  console.log(chalk.dim(`\nProject: ${projectPath}`));
  console.log(
    chalk.dim(
      "Mode: Multi-agent swarm (Recon → Analyze → Exploit)\n"
    )
  );

  const orchestrator = new Orchestrator(config, projectPath);
  const result = await orchestrator.run();

  // Convert to ScanResult for reporting
  const scanResult: ScanResult = {
    projectPath,
    timestamp: new Date().toISOString(),
    duration: result.duration,
    languages: result.recon.techStack,
    filesScanned: 0,
    phase1Findings: result.analysis.findings,
    phase2Findings: [],
    confirmedVulnerabilities: result.analysis.findings,
    dismissedCount: result.analysis.falsePositivesDismissed,
    chains: result.exploit.chains,
  };

  saveResults(projectPath, scanResult);

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          recon: result.recon,
          findings: result.analysis.findings.length,
          chains: result.exploit.chains.length,
          pocs: result.exploit.proofOfConcepts.length,
          tools: result.analysis.toolsUsed,
          insights: result.analysis.aiInsights,
          duration: result.duration,
        },
        null,
        2
      )
    );
  } else {
    // Show AI insights
    if (result.analysis.aiInsights.length > 0) {
      console.log(chalk.bold("\n🧠 AI Insights\n"));
      for (const insight of result.analysis.aiInsights) {
        console.log(chalk.dim(`  → ${insight}`));
      }
    }

    // Show PoCs
    if (result.exploit.proofOfConcepts.length > 0) {
      console.log(chalk.bold("\n💣 Proof of Concepts\n"));
      for (const poc of result.exploit.proofOfConcepts) {
        console.log(
          `  ${chalk.red(poc.vulnerabilityId)} — ${poc.description}`
        );
        console.log(chalk.dim(`    Payload: ${poc.payload}`));
        console.log();
      }
    }

    // Standard vulnerability report
    renderTerminalReport(scanResult);
  }
}
