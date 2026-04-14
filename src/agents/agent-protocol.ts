import type { Vulnerability, VulnChain, Severity } from "../types/index.js";

/**
 * Message types exchanged between agents in the swarm.
 */

export interface ReconReport {
  type: "recon";
  entryPoints: Array<{
    path: string;
    method?: string;
    file: string;
    line: number;
    description: string;
  }>;
  techStack: string[];
  authBoundaries: Array<{
    file: string;
    line: number;
    description: string;
  }>;
  dataStores: Array<{
    type: string;
    file: string;
    description: string;
  }>;
  attackSurface: string; // AI-generated summary
}

export interface AnalysisReport {
  type: "analysis";
  findings: Vulnerability[];
  toolsUsed: string[];
  aiInsights: string[];
  falsePositivesDismissed: number;
}

export interface ExploitReport {
  type: "exploit";
  chains: VulnChain[];
  proofOfConcepts: Array<{
    vulnerabilityId: string;
    payload: string;
    description: string;
    verified: boolean;
  }>;
}

export interface FinalReport {
  type: "final";
  summary: string;
  trustScore: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  chains: VulnChain[];
  topRisks: string[];
  remediationPlan: string;
}

export interface HypothesisReport {
  type: "hypothesis";
  hypotheses: Array<{
    id: string;
    functionName: string;
    file: string;
    line: number;
    hypothesis: string;
    category: string;
    estimatedSeverity: Severity;
    reasoning: string;
    investigationSteps: string[];
  }>;
}

/**
 * Confidence tiers for findings — only "confirmed" and "likely" are reported by default.
 */
export type ConfidenceTier = "confirmed" | "likely" | "possible" | "dismissed";

export type AgentReport =
  | ReconReport
  | HypothesisReport
  | AnalysisReport
  | ExploitReport
  | FinalReport;

export interface AgentTask {
  id: string;
  agent: "recon" | "hypothesis" | "analyzer" | "exploit" | "reporter";
  description: string;
  input: Record<string, unknown>;
  dependsOn?: string[];
}
