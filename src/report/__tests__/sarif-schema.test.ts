import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { renderSarifReport } from "../sarif-reporter.js";
import type { ScanResult, Vulnerability } from "../../types/index.js";

// ajv-draft-04 is a CommonJS module; the default-export interop across
// ESM is most reliable via createRequire. SARIF 2.1.0 pins to
// $schema = http://json-schema.org/draft-04/schema#.
const require = createRequire(import.meta.url);
const Ajv = require("ajv-draft-04") as typeof import("ajv-draft-04").default;

/**
 * SARIF 2.1.0 JSON-Schema conformance.
 *
 * GitHub Code Scanning silently drops invalid SARIF uploads. Without
 * this test, a schema drift (wrong property shape, missing required
 * field) ships to production and the dashboard just... stops getting
 * results, with no alert. The only feedback loop is a user noticing
 * the missing findings.
 *
 * Schema is vendored at fixtures/sarif-schema-2.1.0.json (frozen spec
 * since 2020; source:
 * https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json).
 * Re-download with:
 *   curl -fsSL <url> -o src/report/__tests__/fixtures/sarif-schema-2.1.0.json
 */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCHEMA_PATH = path.join(__dirname, "fixtures", "sarif-schema-2.1.0.json");

function mockVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "SPX-0001",
    rule: "sql-injection",
    title: "SQL Injection",
    description: "User input concatenated into SQL query",
    severity: "critical",
    category: "injection",
    cwe: "CWE-89",
    confidence: "high",
    location: { file: "src/api.ts", line: 42, column: 13, snippet: "db.query(input)" },
    ...overrides,
  };
}

function mockResult(vulns: Vulnerability[] = []): ScanResult {
  return {
    projectPath: "/test/project",
    timestamp: "2026-04-19T00:00:00.000Z",
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

// Shared validator — schema compile is the expensive step; reuse.
const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf-8"));
const ajv = new Ajv({
  strict: false, // SARIF schema uses format/regex patterns Ajv warns about otherwise
  allErrors: true,
  allowUnionTypes: true,
});
const validate = ajv.compile(schema);

describe("SARIF 2.1.0 schema conformance", () => {
  it("empty result produces schema-valid SARIF", () => {
    const output = JSON.parse(renderSarifReport(mockResult([])));
    const ok = validate(output);
    if (!ok) console.error("SARIF validation errors:", validate.errors);
    expect(ok).toBe(true);
  });

  it("single-vulnerability result produces schema-valid SARIF", () => {
    const output = JSON.parse(renderSarifReport(mockResult([mockVuln()])));
    const ok = validate(output);
    if (!ok) console.error("SARIF validation errors:", validate.errors);
    expect(ok).toBe(true);
  });

  it("multi-vulnerability result with varied rules produces schema-valid SARIF", () => {
    const vulns = [
      mockVuln({ id: "SPX-0001", rule: "sql-injection" }),
      mockVuln({
        id: "SPX-0002",
        rule: "xss-unescaped",
        title: "XSS",
        severity: "high",
        category: "xss",
        cwe: "CWE-79",
      }),
      mockVuln({
        id: "SPX-0003",
        rule: "weak-crypto",
        title: "Weak hash algorithm",
        severity: "medium",
        category: "crypto",
        cwe: "CWE-327",
      }),
      mockVuln({
        id: "SPX-0004",
        rule: "info-disclosure",
        title: "Verbose error",
        severity: "low",
        category: "info-disclosure",
        cwe: undefined, // exercise the no-CWE code path
      }),
    ];
    const output = JSON.parse(renderSarifReport(mockResult(vulns)));
    const ok = validate(output);
    if (!ok) console.error("SARIF validation errors:", validate.errors);
    expect(ok).toBe(true);
  });

  it("severity=info maps to level=none and remains schema-valid", () => {
    const output = JSON.parse(renderSarifReport(mockResult([mockVuln({ severity: "info" })])));
    const ok = validate(output);
    if (!ok) console.error("SARIF validation errors:", validate.errors);
    expect(ok).toBe(true);
    expect(output.runs[0].results[0].level).toBe("none");
  });

  it("driver version tracks the package version (no hardcoded drift)", () => {
    const output = JSON.parse(renderSarifReport(mockResult([mockVuln()])));
    const driverVersion =
      output.runs[0].tool.driver.name === "mythos-agent"
        ? output.runs[0].tool.driver.version
        : null;
    // Must look like a semver — not the old hardcoded "0.2.0" or "1.0.0".
    expect(driverVersion).toMatch(/^\d+\.\d+\.\d+(?:[-+].*)?$/);
    expect(driverVersion).not.toBe("0.2.0");
    expect(driverVersion).not.toBe("1.0.0");
  });

  it("location with windows-style path backslashes is normalized to forward slashes", () => {
    const output = JSON.parse(
      renderSarifReport(
        mockResult([
          mockVuln({
            location: { file: "src\\windows\\path.ts", line: 1, column: 1, snippet: "x" },
          }),
        ])
      )
    );
    const uri = output.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(uri).not.toContain("\\");
    expect(uri).toContain("/");
  });
});
