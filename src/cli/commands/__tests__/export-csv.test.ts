/**
 * Focused tests for Fix 2: exportCsv CSV-escaping hardening.
 *
 * exportCsv is an internal function, so we exercise it via exportCommand
 * (writing results to disk with saveResults, then exporting). The key
 * failure mode is: a file path or field containing a comma or newline must
 * NOT introduce extra columns or rows in the CSV output.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { exportCommand } from "../export.js";
import { saveResults } from "../../../store/results-store.js";
import type { ScanResult } from "../../../types/index.js";

let tmpDir: string;

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-export-csv-"));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function makeResult(
  overrides: Partial<ScanResult["confirmedVulnerabilities"][0]> = {}
): ScanResult {
  const base: ScanResult["confirmedVulnerabilities"][0] = {
    id: "IMP-0001",
    rule: "test:rule",
    title: "Test Finding",
    description: "desc",
    severity: "high",
    category: "injection",
    confidence: "high",
    location: { file: "src/app.ts", line: 42 },
    ...overrides,
  };
  return {
    projectPath: tmpDir,
    timestamp: new Date().toISOString(),
    duration: 0,
    languages: [],
    filesScanned: 0,
    phase1Findings: [base],
    phase2Findings: [],
    confirmedVulnerabilities: [base],
    dismissedCount: 0,
    chains: [],
  };
}

describe("exportCsv — CSV-escape fix", () => {
  it("benign fields (no commas/quotes/newlines) produce a clean single-row CSV", async () => {
    saveResults(tmpDir, makeResult());
    const outFile = path.join(tmpDir, "out.csv");
    await exportCommand({ path: tmpDir, format: "csv", output: outFile });

    const lines = fs.readFileSync(outFile, "utf-8").split("\n").filter(Boolean);
    // header + 1 data row
    expect(lines).toHaveLength(2);
    // 8 columns: ID,Severity,Title,Category,CWE,File,Line,Snippet
    expect(lines[1].split(",")).toHaveLength(8);
  });

  it("comma in location.file does NOT inject an extra column", async () => {
    saveResults(tmpDir, makeResult({ location: { file: "src/foo,bar.ts", line: 10 } }));
    const outFile = path.join(tmpDir, "out.csv");
    await exportCommand({ path: tmpDir, format: "csv", output: outFile });

    const content = fs.readFileSync(outFile, "utf-8");
    const lines = content.split("\n").filter(Boolean);
    expect(lines).toHaveLength(2); // still header + 1 data row (no injected row)

    // Parse the data row as CSV-aware: quoted fields don't split on internal commas.
    // The simplest check: the file path "src/foo,bar.ts" must appear as a quoted
    // field ("src/foo,bar.ts") so the column count is still 8.
    expect(content).toContain('"src/foo,bar.ts"');

    // Count top-level (unquoted) commas = 7 for 8 fields.
    // We verify by checking the quoted field is present and the row contains it.
    const dataRow = lines[1];
    // The row must contain the quoted field — the comma is inside quotes.
    expect(dataRow).toContain('"src/foo,bar.ts"');
  });

  it("double-quote in title is properly escaped as two double-quotes", async () => {
    saveResults(tmpDir, makeResult({ title: 'SQL "injection" risk' }));
    const outFile = path.join(tmpDir, "out.csv");
    await exportCommand({ path: tmpDir, format: "csv", output: outFile });

    const content = fs.readFileSync(outFile, "utf-8");
    // CSV escaping: a " inside a quoted field becomes ""
    expect(content).toContain('"SQL ""injection"" risk"');
  });

  it("newline in title does NOT inject an extra row", async () => {
    saveResults(tmpDir, makeResult({ title: "line1\nline2" }));
    const outFile = path.join(tmpDir, "out.csv");
    await exportCommand({ path: tmpDir, format: "csv", output: outFile });

    const content = fs.readFileSync(outFile, "utf-8");
    // The newline is inside a quoted field — it must appear quoted
    expect(content).toContain('"line1\nline2"');
  });
});
