import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { evaluatePolicy, getComplianceMapping, loadPolicy } from "../engine.js";
import type { ScanResult, Vulnerability, VulnChain } from "../../types/index.js";

const tmpDirs: string[] = [];

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-policy-"));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

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

describe("loadPolicy — structural validation", () => {
  it("returns null when the policy file has rules as a string (not an array)", () => {
    const dir = tempDir();
    const policyDir = path.join(dir, ".mythos");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(path.join(policyDir, "policy.yml"), "name: bad-policy\nrules: not-an-array\n");
    const result = loadPolicy(dir);
    expect(result).toBeNull();
  });

  it("returns null when the policy file has no name field", () => {
    const dir = tempDir();
    const policyDir = path.join(dir, ".mythos");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(
      path.join(policyDir, "policy.yml"),
      "rules:\n  - id: r1\n    action: block\n    condition:\n      type: severity_threshold\n"
    );
    const result = loadPolicy(dir);
    expect(result).toBeNull();
  });

  it("returns null when a rule is missing the id field", () => {
    const dir = tempDir();
    const policyDir = path.join(dir, ".mythos");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(
      path.join(policyDir, "policy.yml"),
      [
        "name: test",
        "rules:",
        "  - action: block",
        "    condition:",
        "      type: severity_threshold",
      ].join("\n") + "\n"
    );
    const result = loadPolicy(dir);
    expect(result).toBeNull();
  });

  it("returns null when a rule is missing the description field", () => {
    const dir = tempDir();
    const policyDir = path.join(dir, ".mythos");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(
      path.join(policyDir, "policy.yml"),
      [
        "name: test",
        "rules:",
        "  - id: no-critical",
        "    action: block",
        "    condition:",
        "      type: severity_threshold",
      ].join("\n") + "\n"
    );
    const result = loadPolicy(dir);
    expect(result).toBeNull();
  });

  it("returns null when rules field is missing entirely", () => {
    const dir = tempDir();
    const policyDir = path.join(dir, ".mythos");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(path.join(policyDir, "policy.yml"), "name: empty-policy\n");
    const result = loadPolicy(dir);
    expect(result).toBeNull();
  });

  it("loads a well-formed policy with empty rules array successfully", () => {
    const dir = tempDir();
    const policyDir = path.join(dir, ".mythos");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(path.join(policyDir, "policy.yml"), "name: minimal\nrules: []\n");
    const result = loadPolicy(dir);
    expect(result).not.toBeNull();
    expect(result!.name).toBe("minimal");
    expect(result!.rules).toEqual([]);
  });

  it("loads a well-formed policy with a valid rule successfully", () => {
    const dir = tempDir();
    const policyDir = path.join(dir, ".mythos");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(
      path.join(policyDir, "policy.yml"),
      [
        "name: valid-policy",
        "description: A valid policy",
        "rules:",
        "  - id: no-critical",
        "    description: No critical vulns",
        "    action: block",
        "    condition:",
        "      type: severity_threshold",
        "      severity: critical",
      ].join("\n") + "\n"
    );
    const result = loadPolicy(dir);
    expect(result).not.toBeNull();
    expect(result!.name).toBe("valid-policy");
    expect(result!.rules).toHaveLength(1);
    expect(result!.rules[0].id).toBe("no-critical");
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
