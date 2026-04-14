import chalk from "chalk";
import ora from "ora";
import type { SphinxConfig } from "../types/index.js";
import type { Vulnerability, VulnChain, ScanResult } from "../types/index.js";
import { ReconAgent } from "./recon-agent.js";
import { AnalyzerAgent } from "./analyzer-agent.js";
import { ExploitAgent } from "./exploit-agent.js";
import type { ReconReport, AnalysisReport, ExploitReport } from "./agent-protocol.js";

export interface OrchestratorResult {
  recon: ReconReport;
  analysis: AnalysisReport;
  exploit: ExploitReport;
  duration: number;
}

/**
 * The Orchestrator coordinates the multi-agent security scan.
 *
 * Pipeline: Recon → Analyze → Exploit → Report
 * Each agent receives the output of the previous phase.
 */
export class Orchestrator {
  constructor(
    private config: SphinxConfig,
    private projectPath: string,
    private silent = false
  ) {}

  async run(): Promise<OrchestratorResult> {
    const start = Date.now();

    // Phase 1: Reconnaissance
    const reconSpinner = this.spinner("Phase 1: Reconnaissance — mapping attack surface");
    const reconAgent = new ReconAgent(this.config, this.projectPath);
    const recon = await reconAgent.execute();
    this.succeed(reconSpinner,
      `Reconnaissance — ${recon.entryPoints.length} entry points, ${recon.techStack.join(", ")}`
    );

    // Phase 2: Analysis (uses recon output to focus scanning)
    const analysisSpinner = this.spinner("Phase 2: Analysis — scanning for vulnerabilities");
    const analyzerAgent = new AnalyzerAgent(this.config, this.projectPath);
    const analysis = await analyzerAgent.execute(recon);
    this.succeed(analysisSpinner,
      `Analysis — ${analysis.findings.length} findings (${analysis.toolsUsed.join(", ")}), ${analysis.falsePositivesDismissed} false positives dismissed`
    );

    // Phase 3: Exploitation (chain + verify findings)
    const exploitSpinner = this.spinner("Phase 3: Exploitation — chaining and verifying");
    const exploitAgent = new ExploitAgent(this.config, this.projectPath);
    const exploit = await exploitAgent.execute(analysis, recon);
    this.succeed(exploitSpinner,
      `Exploitation — ${exploit.chains.length} attack chains, ${exploit.proofOfConcepts.length} PoCs`
    );

    return {
      recon,
      analysis,
      exploit,
      duration: Date.now() - start,
    };
  }

  private spinner(text: string) {
    return this.silent ? null : ora(text).start();
  }

  private succeed(spinner: ReturnType<typeof ora> | null, text: string) {
    if (spinner) spinner.succeed(text);
  }
}
