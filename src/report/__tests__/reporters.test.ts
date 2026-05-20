import { describe, it, expect, vi } from "vitest";
import { renderSarifReport } from "../sarif-reporter.js";
import { renderMarkdownReport } from "../markdown-reporter.js";
import { renderComplianceMarkdown } from "../compliance-reporter.js";
import { renderJsonReport } from "../json-reporter.js";
import { buildDashboardHtml } from "../dashboard-html.js";
import { buildHtml } from "../html-reporter.js";
import { VERSION } from "../../version.js";
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

describe("Markdown Reporter", () => {
  it("contains the real VERSION and not the stale literal", () => {
    const output = renderMarkdownReport(mockResult([]), "/some/project");
    expect(output).toContain(`mythos-agent v${VERSION}`);
    expect(output).not.toContain("v1.0.0");
  });
});

describe("Compliance Reporter", () => {
  it("contains the real VERSION and not the stale literal", () => {
    const output = renderComplianceMarkdown(mockResult([]), [], "/some/project");
    expect(output).toContain(`mythos-agent v${VERSION}`);
    expect(output).not.toContain("v1.0.0");
  });
});

describe("JSON Reporter", () => {
  it("returns a string (does not print to stdout)", () => {
    const consoleSpy = vi.spyOn(console, "log");
    const output = renderJsonReport(mockResult([]));
    expect(typeof output).toBe("string");
    expect(consoleSpy).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it("contains the real VERSION and not the stale literal", () => {
    const output = renderJsonReport(mockResult([]));
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe(VERSION);
    expect(parsed.version).not.toBe("0.1.0");
  });

  it("preserves expected JSON structure", () => {
    const output = renderJsonReport(mockResult([mockVuln()]));
    const parsed = JSON.parse(output);
    expect(parsed).toHaveProperty("timestamp");
    expect(parsed).toHaveProperty("project");
    expect(parsed).toHaveProperty("summary");
    expect(parsed).toHaveProperty("vulnerabilities");
    expect(parsed.vulnerabilities).toHaveLength(1);
  });
});

describe("SARIF Reporter", () => {
  it("produces valid SARIF 2.1.0 structure", () => {
    const sarif = JSON.parse(renderSarifReport(mockResult([mockVuln()])));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("mythos-agent");
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

describe("HTML escaping of vuln.id", () => {
  const xssId = "<script>alert(1)</script>";

  it("html-reporter: escapes vuln.id — does not emit raw script tag", () => {
    const html = buildHtml(mockResult([mockVuln({ id: xssId })]));
    expect(html).not.toContain(xssId);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("dashboard-html: escapes v.id — does not emit raw script tag", () => {
    const html = buildDashboardHtml(mockResult([mockVuln({ id: xssId })]), "/test/project");
    expect(html).not.toContain(xssId);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});
