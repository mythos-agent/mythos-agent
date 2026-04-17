import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import type { ScanResult, Vulnerability, Severity } from "../types/index.js";

export interface Policy {
  name: string;
  description?: string;
  rules: PolicyRule[];
}

export interface PolicyRule {
  id: string;
  description: string;
  action: "block" | "warn";
  condition: PolicyCondition;
  compliance?: string[]; // SOC2, HIPAA, PCI-DSS, OWASP
}

export interface PolicyCondition {
  type: "severity_threshold" | "category_match" | "rule_match" | "count_threshold" | "trust_score";
  severity?: Severity;
  categories?: string[];
  rules?: string[];
  maxCount?: number;
  minScore?: number;
}

export interface PolicyResult {
  passed: boolean;
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
}

export interface PolicyViolation {
  ruleId: string;
  description: string;
  action: "block" | "warn";
  matchedFindings: Vulnerability[];
  compliance?: string[];
}

const DEFAULT_POLICY_PATH = ".sphinx/policy.yml";

const COMPLIANCE_MAP: Record<string, Record<string, string>> = {
  SOC2: {
    injection: "CC6.1 — Logical and Physical Access Controls",
    xss: "CC6.1 — Logical and Physical Access Controls",
    secrets: "CC6.1 — Confidentiality of Information Assets",
    crypto: "CC6.1 — Cryptographic Key Management",
    auth: "CC6.1 — Authentication Mechanisms",
  },
  HIPAA: {
    injection: "§164.312(a)(1) — Access Control",
    secrets: "§164.312(a)(2)(iv) — Encryption and Decryption",
    crypto: "§164.312(e)(1) — Transmission Security",
    auth: "§164.312(d) — Person or Entity Authentication",
  },
  "PCI-DSS": {
    injection: "Req 6.5.1 — Injection Flaws",
    xss: "Req 6.5.7 — Cross-Site Scripting",
    secrets: "Req 3.4 — Render PAN Unreadable",
    crypto: "Req 4.1 — Strong Cryptography",
    auth: "Req 8.2 — Authentication Management",
  },
  OWASP: {
    injection: "A03:2021 — Injection",
    xss: "A03:2021 — Injection",
    secrets: "A02:2021 — Cryptographic Failures",
    crypto: "A02:2021 — Cryptographic Failures",
    auth: "A07:2021 — Identification and Authentication Failures",
    ssrf: "A10:2021 — Server-Side Request Forgery",
    iac: "A05:2021 — Security Misconfiguration",
    dependency: "A06:2021 — Vulnerable and Outdated Components",
  },
};

export function loadPolicy(projectPath: string): Policy | null {
  const policyPath = path.join(projectPath, DEFAULT_POLICY_PATH);
  if (!fs.existsSync(policyPath)) return null;

  try {
    const raw = fs.readFileSync(policyPath, "utf-8");
    return yaml.load(raw) as Policy;
  } catch {
    return null;
  }
}

export function evaluatePolicy(policy: Policy, result: ScanResult): PolicyResult {
  const violations: PolicyViolation[] = [];
  const warnings: PolicyViolation[] = [];
  const vulns = result.confirmedVulnerabilities;

  for (const rule of policy.rules) {
    const matched = evaluateCondition(rule.condition, vulns, result);
    if (matched.length > 0) {
      const violation: PolicyViolation = {
        ruleId: rule.id,
        description: rule.description,
        action: rule.action,
        matchedFindings: matched,
        compliance: rule.compliance,
      };

      if (rule.action === "block") {
        violations.push(violation);
      } else {
        warnings.push(violation);
      }
    }
  }

  return {
    passed: violations.length === 0,
    violations,
    warnings,
  };
}

function evaluateCondition(
  condition: PolicyCondition,
  vulns: Vulnerability[],
  result: ScanResult
): Vulnerability[] {
  const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

  switch (condition.type) {
    case "severity_threshold": {
      const threshold = severityOrder.indexOf(condition.severity || "critical");
      return vulns.filter((v) => severityOrder.indexOf(v.severity) <= threshold);
    }

    case "category_match":
      return vulns.filter((v) => (condition.categories || []).includes(v.category));

    case "rule_match":
      return vulns.filter((v) =>
        (condition.rules || []).some((r) => v.rule === r || v.rule.startsWith(r))
      );

    case "count_threshold": {
      const max = condition.maxCount ?? 0;
      return vulns.length > max ? vulns : [];
    }

    case "trust_score": {
      const score = calculateTrustScore(vulns, result.chains);
      const min = condition.minScore ?? 7;
      return score < min ? vulns : [];
    }

    default:
      return [];
  }
}

function calculateTrustScore(vulns: Vulnerability[], chains: ScanResult["chains"]): number {
  let score = 10;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        score -= 2;
        break;
      case "high":
        score -= 1;
        break;
      case "medium":
        score -= 0.5;
        break;
      case "low":
        score -= 0.2;
        break;
    }
  }
  for (const chain of chains) {
    switch (chain.severity) {
      case "critical":
        score -= 1.5;
        break;
      case "high":
        score -= 1;
        break;
      default:
        score -= 0.5;
    }
  }
  return Math.max(0, Math.min(10, score));
}

export function getComplianceMapping(finding: Vulnerability, frameworks: string[]): string[] {
  const mappings: string[] = [];
  for (const framework of frameworks) {
    const map = COMPLIANCE_MAP[framework];
    if (map && map[finding.category]) {
      mappings.push(`${framework}: ${map[finding.category]}`);
    }
  }
  return mappings;
}

export function generateDefaultPolicy(): string {
  return `# sphinx-agent Policy Configuration
# Place at .sphinx/policy.yml

name: default
description: Default security policy

rules:
  # Block merges with critical vulnerabilities
  - id: no-critical
    description: "No critical vulnerabilities allowed"
    action: block
    condition:
      type: severity_threshold
      severity: critical
    compliance: [OWASP, PCI-DSS, SOC2]

  # Block merges with hardcoded secrets
  - id: no-secrets
    description: "No hardcoded secrets in source code"
    action: block
    condition:
      type: category_match
      categories: [secrets]
    compliance: [SOC2, HIPAA, PCI-DSS]

  # Warn on high severity issues
  - id: warn-high
    description: "High severity vulnerabilities should be reviewed"
    action: warn
    condition:
      type: severity_threshold
      severity: high

  # Block if trust score is too low
  - id: min-trust-score
    description: "Project trust score must be at least 5.0"
    action: block
    condition:
      type: trust_score
      minScore: 5

  # Warn on SQL injection
  - id: no-sqli
    description: "SQL injection vulnerabilities detected"
    action: warn
    condition:
      type: rule_match
      rules: [sql-injection, go-sql-injection, java-sql-injection, php-sql-injection]
    compliance: [OWASP, PCI-DSS]
`;
}
