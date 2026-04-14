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

export type AgentReport =
  | ReconReport
  | AnalysisReport
  | ExploitReport
  | FinalReport;

export interface AgentTask {
  id: string;
  agent: "recon" | "analyzer" | "exploit" | "reporter";
  description: string;
  input: Record<string, unknown>;
  dependsOn?: string[];
}
