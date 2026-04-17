import chalk from "chalk";
import ora from "ora";
import type { SphinxConfig } from "../types/index.js";
import type { Vulnerability, VulnChain, ScanResult } from "../types/index.js";
import { ReconAgent } from "./recon-agent.js";
import { HypothesisAgent, type SecurityHypothesis } from "./hypothesis-agent.js";
import { AnalyzerAgent } from "./analyzer-agent.js";
import { ExploitAgent } from "./exploit-agent.js";
import type {
  ReconReport,
  HypothesisReport,
  AnalysisReport,
  ExploitReport,
} from "./agent-protocol.js";

export interface OrchestratorResult {
  recon: ReconReport;
  hypotheses: HypothesisReport;
  analysis: AnalysisReport;
  exploit: ExploitReport;
  duration: number;
  confidenceSummary: {
    confirmed: number;
    likely: number;
    possible: number;
    dismissed: number;
  };
}

/**
 * The Orchestrator coordinates the multi-agent security scan.
 *
 * Pipeline: Recon → Hypothesize → Analyze → Exploit → Report
 *
 * The hypothesis phase is what makes this a "security researcher"
 * instead of a "scanner" — it REASONS about what could go wrong
 * before pattern matching.
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
    this.succeed(
      reconSpinner,
      `Reconnaissance — ${recon.entryPoints.length} entry points, ${recon.techStack.join(", ") || "detected"}`
    );

    // Phase 2: Hypothesis Generation (the Mythos differentiator)
    let hypotheses: HypothesisReport = { type: "hypothesis", hypotheses: [] };
    if (this.config.apiKey) {
      const hypoSpinner = this.spinner("Phase 2: Hypothesis — reasoning about what could go wrong");
      try {
        const hypothesisAgent = new HypothesisAgent(this.config, this.projectPath);
        hypotheses = await hypothesisAgent.execute(recon);
        this.succeed(
          hypoSpinner,
          `Hypothesis — ${hypotheses.hypotheses.length} security hypotheses generated`
        );
      } catch (err) {
        if (hypoSpinner)
          hypoSpinner.warn(
            `Hypothesis — skipped (${err instanceof Error ? err.message : "error"})`
          );
      }
    }

    // Phase 3: Analysis (uses recon + hypotheses to focus scanning)
    const analysisSpinner = this.spinner("Phase 3: Analysis — scanning for vulnerabilities");
    const analyzerAgent = new AnalyzerAgent(this.config, this.projectPath);
    const analysis = await analyzerAgent.execute(recon);

    // Merge hypothesis-derived findings into analysis
    if (hypotheses.hypotheses.length > 0) {
      const hypothesisAgent = new HypothesisAgent(this.config, this.projectPath);
      const hypoFindings = hypothesisAgent.hypothesesToVulnerabilities(hypotheses.hypotheses);
      analysis.findings.push(...hypoFindings);
      analysis.aiInsights.push(
        `Hypothesis agent generated ${hypotheses.hypotheses.length} security hypotheses covering: ${[...new Set(hypotheses.hypotheses.map((h) => h.category))].join(", ")}`
      );
    }

    this.succeed(
      analysisSpinner,
      `Analysis — ${analysis.findings.length} findings (${analysis.toolsUsed.join(", ")}), ${analysis.falsePositivesDismissed} false positives dismissed`
    );

    // Phase 4: Exploitation (chain + verify findings)
    const exploitSpinner = this.spinner("Phase 4: Exploitation — chaining and verifying");
    const exploitAgent = new ExploitAgent(this.config, this.projectPath);
    const exploit = await exploitAgent.execute(analysis, recon);
    this.succeed(
      exploitSpinner,
      `Exploitation — ${exploit.chains.length} attack chains, ${exploit.proofOfConcepts.length} PoCs`
    );

    // Compute confidence summary
    const confidenceSummary = {
      confirmed: exploit.proofOfConcepts.filter((p) => p.verified).length,
      likely: analysis.findings.filter((f) => f.aiVerified).length,
      possible: analysis.findings.filter((f) => !f.aiVerified && f.confidence === "medium").length,
      dismissed: analysis.falsePositivesDismissed,
    };

    return {
      recon,
      hypotheses,
      analysis,
      exploit,
      duration: Date.now() - start,
      confidenceSummary,
    };
  }

  private spinner(text: string) {
    return this.silent ? null : ora(text).start();
  }

  private succeed(spinner: ReturnType<typeof ora> | null, text: string) {
    if (spinner) spinner.succeed(text);
  }
}
