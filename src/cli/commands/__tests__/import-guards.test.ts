/**
 * Focused tests for Fix 4: import.ts guard hardening.
 *
 * Covers:
 *  - Malformed JSON in each importer throws a clear error (not a raw
 *    SyntaxError crash with no context).
 *  - File size guard rejects files > 50 MB.
 *  - Invalid severity in Snyk import is coerced to "info".
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { importCommand } from "../import.js";

let tmpDir: string;

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-import-guards-"));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeFile(name: string, content: string): string {
  const p = path.join(tmpDir, name);
  fs.writeFileSync(p, content, "utf-8");
  return p;
}

describe("import guards — malformed JSON", () => {
  it("rejects a malformed Snyk file with a clear JSON error (not raw SyntaxError crash)", async () => {
    const file = writeFile("snyk.json", "{not valid json");
    await expect(importCommand(file, { format: "snyk", path: tmpDir })).rejects.toThrow(
      /Failed to parse Snyk file as JSON/
    );
  });

  it("rejects a malformed SARIF file with a clear JSON error", async () => {
    const file = writeFile("results.sarif", "{not valid json");
    await expect(importCommand(file, { format: "sarif", path: tmpDir })).rejects.toThrow(
      /Failed to parse SARIF file as JSON/
    );
  });

  it("rejects a malformed Semgrep file with a clear JSON error", async () => {
    const file = writeFile("semgrep.json", "{not valid json");
    await expect(importCommand(file, { format: "semgrep", path: tmpDir })).rejects.toThrow(
      /Failed to parse Semgrep file as JSON/
    );
  });

  it("rejects a malformed Trivy file with a clear JSON error", async () => {
    const file = writeFile("trivy.json", "{not valid json");
    await expect(importCommand(file, { format: "trivy", path: tmpDir })).rejects.toThrow(
      /Failed to parse Trivy file as JSON/
    );
  });
});

describe("import guards — file size guard", () => {
  it("throws 'too large' before reading when fs.statSync reports > 50 MB", async () => {
    // Create a real (small) file then mock statSync to report a huge size.
    const file = writeFile("huge.json", "{}");
    const statSpy = vi.spyOn(fs, "statSync").mockReturnValueOnce({
      size: 51 * 1024 * 1024, // 51 MB
    } as ReturnType<typeof fs.statSync>);

    await expect(importCommand(file, { format: "snyk", path: tmpDir })).rejects.toThrow(
      /too large/
    );

    statSpy.mockRestore();
  });
});

describe("import guards — Snyk severity validation", () => {
  it("coerces unknown severity values to 'info'", async () => {
    const snykData = {
      vulnerabilities: [
        {
          id: "SNYK-001",
          title: "Bad thing",
          description: "desc",
          severity: "TOTALLY-BOGUS",
        },
      ],
    };
    const file = writeFile("snyk.json", JSON.stringify(snykData));

    // Import should succeed (no throw) and produce a finding
    const { saveResults, loadResults } = await import("../../../store/results-store.js");
    await importCommand(file, { format: "snyk", path: tmpDir });

    const result = loadResults(tmpDir);
    expect(result).not.toBeNull();
    expect(result!.confirmedVulnerabilities).toHaveLength(1);
    // Invalid severity must have been coerced to "info"
    expect(result!.confirmedVulnerabilities[0].severity).toBe("info");
  });

  it("preserves valid severity values unchanged", async () => {
    const snykData = {
      vulnerabilities: [
        { id: "SNYK-002", title: "High finding", description: "", severity: "high" },
        { id: "SNYK-003", title: "Critical finding", description: "", severity: "critical" },
        { id: "SNYK-004", title: "Info finding", description: "", severity: "info" },
      ],
    };
    const file = writeFile("snyk2.json", JSON.stringify(snykData));
    const { loadResults } = await import("../../../store/results-store.js");

    await importCommand(file, { format: "snyk", path: tmpDir });

    const result = loadResults(tmpDir);
    expect(result).not.toBeNull();
    const severities = result!.confirmedVulnerabilities.map((v) => v.severity);
    expect(severities).toEqual(["high", "critical", "info"]);
  });
});
