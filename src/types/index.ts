export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Location {
  file: string;
  line: number;
  column?: number;
  snippet?: string;
}

export interface Vulnerability {
  id: string;
  rule: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  location: Location;
  cwe?: string;
  confidence: "high" | "medium" | "low";
  aiVerified?: boolean;
  falsePositive?: boolean;
}

export interface VulnChain {
  id: string;
  title: string;
  severity: Severity;
  vulnerabilities: Vulnerability[];
  narrative: string;
  impact: string;
}

export interface ScanResult {
  projectPath: string;
  timestamp: string;
  duration: number;
  languages: string[];
  filesScanned: number;
  phase1Findings: Vulnerability[];
  phase2Findings: Vulnerability[];
  confirmedVulnerabilities: Vulnerability[];
  dismissedCount: number;
  chains: VulnChain[];
}

export interface RuleDefinition {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  cwe?: string;
  languages: string[];
  patterns: RulePattern[];
}

export interface RulePattern {
  type: "regex" | "ast";
  pattern: string;
  message?: string;
}

export interface SphinxConfig {
  apiKey?: string;
  model: string;
  provider: string; // "anthropic" | "openai" | "ollama" | "lmstudio" | "vllm" | custom
  rules: {
    enabled: string[];
    disabled: string[];
  };
  scan: {
    include: string[];
    exclude: string[];
    maxFileSize: number;
    severityThreshold: Severity;
  };
}

export const DEFAULT_CONFIG: SphinxConfig = {
  model: "claude-sonnet-4-20250514",
  provider: "anthropic",
  rules: {
    enabled: ["*"],
    disabled: [],
  },
  scan: {
    include: [
      "**/*.ts",
      "**/*.tsx",
      "**/*.js",
      "**/*.jsx",
      "**/*.py",
      "**/*.go",
      "**/*.java",
      "**/*.php",
    ],
    exclude: [
      "node_modules/**",
      "dist/**",
      "build/**",
      ".git/**",
      ".sphinx/**",
      "**/*.test.*",
      "**/*.spec.*",
      "**/*.min.js",
      "**/package-lock.json",
      "**/yarn.lock",
    ],
    maxFileSize: 100_000,
    severityThreshold: "low",
  },
};
