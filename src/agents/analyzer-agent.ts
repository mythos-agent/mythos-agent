import type { SphinxConfig, Vulnerability } from "../types/index.js";
import type { ReconReport, AnalysisReport } from "./agent-protocol.js";
import { PatternScanner } from "../scanner/pattern-scanner.js";
import { SecretsScanner } from "../scanner/secrets-scanner.js";
import { IacScanner } from "../scanner/iac-scanner.js";
import { DepScanner } from "../scanner/dep-scanner.js";
import { runAllTools } from "../tools/index.js";
import { AIAnalyzer } from "../agent/analyzer.js";

/**
 * The Analyzer Agent runs all scanning tools and uses AI to verify findings.
 * It combines built-in scanners with external tools when available.
 */
export class AnalyzerAgent {
  constructor(
    private config: SphinxConfig,
    private projectPath: string
  ) {}

  async execute(recon: ReconReport): Promise<AnalysisReport> {
    const allFindings: Vulnerability[] = [];
    const toolsUsed: string[] = [];
    const aiInsights: string[] = [];

    // 1. Run built-in scanners (always available)
    const patternScanner = new PatternScanner(this.config);
    const { findings: patternFindings } = await patternScanner.scan(this.projectPath);
    allFindings.push(...patternFindings);
    toolsUsed.push("built-in-patterns");

    const secretsScanner = new SecretsScanner();
    const { findings: secretsFindings } = await secretsScanner.scan(this.projectPath);
    allFindings.push(...secretsFindings);
    if (secretsFindings.length > 0) toolsUsed.push("built-in-secrets");

    const iacScanner = new IacScanner();
    const { findings: iacFindings } = await iacScanner.scan(this.projectPath);
    allFindings.push(...iacFindings);
    if (iacFindings.length > 0) toolsUsed.push("built-in-iac");

    const depScanner = new DepScanner();
    try {
      const { findings: depFindings } = await depScanner.scan(this.projectPath);
      allFindings.push(...depFindings);
      if (depFindings.length > 0) toolsUsed.push("osv-api");
    } catch {
      // dep scanning is optional
    }

    // 2. Run external tools (when installed)
    const {
      findings: externalFindings,
      toolsRun,
      toolsSkipped,
    } = await runAllTools(this.projectPath);
    allFindings.push(...externalFindings);
    toolsUsed.push(...toolsRun);

    // 3. Deduplicate findings (same file + same line + similar rule)
    const deduped = deduplicateFindings(allFindings);

    // 4. AI verification (if API key available)
    let verified = deduped;
    let dismissedCount = 0;

    if (this.config.apiKey) {
      try {
        const aiAnalyzer = new AIAnalyzer(this.config);
        const aiResult = await aiAnalyzer.analyze(
          this.projectPath,
          deduped.filter((f) => f.category !== "secrets" && f.category !== "dependency")
        );

        // Preserve secrets + deps (AI doesn't verify those)
        const nonAiFindings = deduped.filter(
          (f) => f.category === "secrets" || f.category === "dependency"
        );

        verified = [...aiResult.confirmed, ...aiResult.discovered, ...nonAiFindings];
        dismissedCount = aiResult.dismissedCount;
        toolsUsed.push("ai-analysis");

        if (aiResult.discovered.length > 0) {
          aiInsights.push(
            `AI discovered ${aiResult.discovered.length} additional vulnerabilities not found by tools.`
          );
        }
        if (dismissedCount > 0) {
          aiInsights.push(
            `AI dismissed ${dismissedCount} false positives (${Math.round((dismissedCount / deduped.length) * 100)}% reduction).`
          );
        }
      } catch {
        // AI unavailable — use tool findings as-is
      }
    }

    return {
      type: "analysis",
      findings: verified,
      toolsUsed,
      aiInsights,
      falsePositivesDismissed: dismissedCount,
    };
  }
}

function deduplicateFindings(findings: Vulnerability[]): Vulnerability[] {
  const seen = new Map<string, Vulnerability>();

  for (const f of findings) {
    // Key: file + line + category (allow different tools to find same issue)
    const key = `${f.location.file}:${f.location.line}:${f.category}`;

    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, f);
    } else {
      // Keep the higher-confidence / higher-severity finding
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      if (severityOrder.indexOf(f.severity) < severityOrder.indexOf(existing.severity)) {
        seen.set(key, f);
      }
    }
  }

  return [...seen.values()];
}
