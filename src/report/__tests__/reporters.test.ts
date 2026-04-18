import { describe, it, expect, vi } from "vitest";
import { renderSarifReport } from "../sarif-reporter.js";
import type { ScanResult, Vulnerability } from "../../types/index.js";

function mockResult(vulns: Vulnerability[] = []): ScanResult {
  return {
    projectPath: "/test/project",
    timestamp: "2026-04-14T00:00:00.000Z",
    duration: 500,
    languages: ["typescript"],
    filesScanned: 10,
    phase1Findings: vulns,
    phase2Findings: [],
    confirmedVulnerabilities: vulns,
    dismissedCount: 0,
    chains: [],
  };
}

function mockVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "SPX-0001",
    rule: "sql-injection",
    title: "SQL Injection",
    description: "User input in SQL query",
    severity: "critical",
    category: "injection",
    cwe: "CWE-89",
    confidence: "high",
    location: { file: "src/api.ts", line: 42, snippet: "db.query(input)" },
    ...overrides,
  };
}

describe("SARIF Reporter", () => {
  it("produces valid SARIF 2.1.0 structure", () => {
    const sarif = JSON.parse(renderSarifReport(mockResult([mockVuln()])));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("shedu");
  });

  it("includes all vulnerabilities as results", () => {
    const vulns = [
      mockVuln({ id: "SPX-0001" }),
      mockVuln({ id: "SPX-0002", rule: "xss-unescaped", title: "XSS" }),
    ];
    const sarif = JSON.parse(renderSarifReport(mockResult(vulns)));

    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it("deduplicates rules", () => {
    const vulns = [
      mockVuln({ id: "SPX-0001", rule: "sql-injection" }),
      mockVuln({ id: "SPX-0002", rule: "sql-injection" }),
    ];
    const sarif = JSON.parse(renderSarifReport(mockResult(vulns)));

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it("maps severity to SARIF levels", () => {
    const vulns = [
      mockVuln({ severity: "critical" }),
      mockVuln({ id: "SPX-0002", severity: "medium", rule: "weak-crypto" }),
    ];
    const sarif = JSON.parse(renderSarifReport(mockResult(vulns)));

    expect(sarif.runs[0].results[0].level).toBe("error");
    expect(sarif.runs[0].results[1].level).toBe("warning");
  });

  it("includes file locations with forward slashes", () => {
    const vuln = mockVuln({ location: { file: "src\\api.ts", line: 10 } });
    const sarif = JSON.parse(renderSarifReport(mockResult([vuln])));

    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe("src/api.ts");
    expect(loc.region.startLine).toBe(10);
  });

  it("handles empty results", () => {
    const sarif = JSON.parse(renderSarifReport(mockResult([])));

    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });
});
