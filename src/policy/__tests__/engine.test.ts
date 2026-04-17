import { describe, it, expect } from "vitest";
import { evaluatePolicy, getComplianceMapping } from "../engine.js";
import type { ScanResult, Vulnerability, VulnChain } from "../../types/index.js";

function mockVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "SPX-0001",
    rule: "sql-injection",
    title: "SQL Injection",
    description: "test",
    severity: "high",
    category: "injection",
    confidence: "high",
    location: { file: "test.ts", line: 1 },
    ...overrides,
  };
}

function mockResult(vulns: Vulnerability[]): ScanResult {
  return {
    projectPath: "/test",
    timestamp: new Date().toISOString(),
    duration: 100,
    languages: ["typescript"],
    filesScanned: 1,
    phase1Findings: vulns,
    phase2Findings: [],
    confirmedVulnerabilities: vulns,
    dismissedCount: 0,
    chains: [],
  };
}

describe("evaluatePolicy", () => {
  it("passes when no rules match", () => {
    const result = evaluatePolicy({ name: "test", rules: [] }, mockResult([]));
    expect(result.passed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it("blocks on severity_threshold — critical", () => {
    const result = evaluatePolicy(
      {
        name: "test",
        rules: [
          {
            id: "no-critical",
            description: "No critical vulns",
            action: "block",
            condition: { type: "severity_threshold", severity: "critical" },
          },
        ],
      },
      mockResult([mockVuln({ severity: "critical" })])
    );
    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].ruleId).toBe("no-critical");
  });

  it("does not block when severity is below threshold", () => {
    const result = evaluatePolicy(
      {
        name: "test",
        rules: [
          {
            id: "no-critical",
            description: "No critical vulns",
            action: "block",
            condition: { type: "severity_threshold", severity: "critical" },
          },
        ],
      },
      mockResult([mockVuln({ severity: "medium" })])
    );
    expect(result.passed).toBe(true);
  });

  it("matches by category", () => {
    const result = evaluatePolicy(
      {
        name: "test",
        rules: [
          {
            id: "no-secrets",
            description: "No secrets",
            action: "block",
            condition: { type: "category_match", categories: ["secrets"] },
          },
        ],
      },
      mockResult([mockVuln({ category: "secrets" })])
    );
    expect(result.passed).toBe(false);
  });

  it("warns instead of blocking", () => {
    const result = evaluatePolicy(
      {
        name: "test",
        rules: [
          {
            id: "warn-high",
            description: "Warn on high",
            action: "warn",
            condition: { type: "severity_threshold", severity: "high" },
          },
        ],
      },
      mockResult([mockVuln({ severity: "high" })])
    );
    expect(result.passed).toBe(true); // warnings don't block
    expect(result.warnings).toHaveLength(1);
  });

  it("evaluates trust_score condition", () => {
    // 10 critical vulns = trust score 0
    const vulns = Array.from({ length: 10 }, (_, i) =>
      mockVuln({ id: `SPX-${i}`, severity: "critical" })
    );
    const result = evaluatePolicy(
      {
        name: "test",
        rules: [
          {
            id: "min-score",
            description: "Min trust score 5",
            action: "block",
            condition: { type: "trust_score", minScore: 5 },
          },
        ],
      },
      mockResult(vulns)
    );
    expect(result.passed).toBe(false);
  });

  it("evaluates count_threshold condition", () => {
    const vulns = Array.from({ length: 5 }, (_, i) => mockVuln({ id: `SPX-${i}` }));
    const result = evaluatePolicy(
      {
        name: "test",
        rules: [
          {
            id: "max-3",
            description: "Max 3 vulns",
            action: "block",
            condition: { type: "count_threshold", maxCount: 3 },
          },
        ],
      },
      mockResult(vulns)
    );
    expect(result.passed).toBe(false);
  });
});

describe("getComplianceMapping", () => {
  it("returns SOC2 mapping for injection", () => {
    const vuln = mockVuln({ category: "injection" });
    const mappings = getComplianceMapping(vuln, ["SOC2"]);
    expect(mappings.length).toBe(1);
    expect(mappings[0]).toContain("SOC2");
  });

  it("returns multiple framework mappings", () => {
    const vuln = mockVuln({ category: "injection" });
    const mappings = getComplianceMapping(vuln, ["SOC2", "OWASP", "PCI-DSS"]);
    expect(mappings.length).toBe(3);
  });

  it("returns empty for unmapped category", () => {
    const vuln = mockVuln({ category: "unknown-category" });
    const mappings = getComplianceMapping(vuln, ["SOC2"]);
    expect(mappings).toHaveLength(0);
  });
});
