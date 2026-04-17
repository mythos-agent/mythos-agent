import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { saveBaseline, loadBaseline, compareToBaseline } from "../baseline.js";
import { recordScan, loadHistory, getTrends } from "../history.js";
import { saveResults, loadResults, getResultsPath } from "../results-store.js";
import {
  loadSuppressions,
  addSuppression,
  removeSuppression,
  filterSuppressed,
} from "../suppressions.js";
import type { ScanResult, Vulnerability } from "../../types/index.js";

const tmpDirs: string[] = [];

function makeProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-store-"));
  tmpDirs.push(dir);
  return dir;
}

function makeVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "TEST-0001",
    rule: "sqli:sqli-template-literal",
    title: "Test vulnerability",
    description: "",
    severity: "high",
    category: "sql-injection",
    confidence: "high",
    location: { file: "src/app.ts", line: 10, snippet: "test" },
    ...overrides,
  };
}

function makeResult(vulns: Vulnerability[] = [], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    projectPath: "/tmp",
    timestamp: new Date().toISOString(),
    duration: 100,
    languages: ["typescript"],
    filesScanned: 5,
    phase1Findings: [],
    phase2Findings: [],
    confirmedVulnerabilities: vulns,
    dismissedCount: 0,
    chains: [],
    ...overrides,
  };
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

describe("baseline", () => {
  it("saves and loads a baseline", () => {
    const dir = makeProject();
    const result = makeResult([makeVuln()]);

    const saved = saveBaseline(dir, result);
    expect(fs.existsSync(saved)).toBe(true);

    const loaded = loadBaseline(dir);
    expect(loaded).not.toBeNull();
    expect(loaded!.findings).toHaveLength(1);
    expect(loaded!.findings[0].rule).toBe("sqli:sqli-template-literal");
  });

  it("returns null when no baseline exists", () => {
    const dir = makeProject();
    expect(loadBaseline(dir)).toBeNull();
    expect(compareToBaseline(dir, makeResult())).toBeNull();
  });

  it("detects new and fixed findings vs baseline", () => {
    const dir = makeProject();
    const oldVuln = makeVuln({ id: "OLD-1", location: { file: "a.ts", line: 10, snippet: "" } });
    saveBaseline(dir, makeResult([oldVuln]));

    const newVuln = makeVuln({
      id: "NEW-1",
      rule: "xss:xss-dom-innerhtml",
      location: { file: "b.ts", line: 20, snippet: "" },
    });
    const diff = compareToBaseline(dir, makeResult([newVuln]));

    expect(diff).not.toBeNull();
    expect(diff!.newFindings).toHaveLength(1);
    expect(diff!.newFindings[0].id).toBe("NEW-1");
    expect(diff!.fixedFindings).toHaveLength(1);
    expect(diff!.fixedFindings[0].rule).toBe("sqli:sqli-template-literal");
  });
});

describe("history", () => {
  it("records a scan and loads history", () => {
    const dir = makeProject();
    recordScan(dir, makeResult([makeVuln({ severity: "critical" })]));

    const loaded = loadHistory(dir);
    expect(loaded.scans).toHaveLength(1);
    expect(loaded.scans[0].critical).toBe(1);
    expect(loaded.scans[0].total).toBe(1);
    // Trust score penalizes criticals by 2
    expect(loaded.scans[0].trustScore).toBeLessThanOrEqual(8);
  });

  it("returns empty history when none exists", () => {
    const dir = makeProject();
    const h = loadHistory(dir);
    expect(h.scans).toEqual([]);
  });

  it("exposes trend data across recorded scans", () => {
    const dir = makeProject();
    recordScan(dir, makeResult([makeVuln({ severity: "high" })]));
    recordScan(dir, makeResult([]));

    const trends = getTrends(dir);
    expect(trends.totals).toEqual([1, 0]);
    expect(trends.dates).toHaveLength(2);
    expect(trends.criticals).toEqual([0, 0]);
  });
});

describe("results-store", () => {
  it("saves and loads scan results", () => {
    const dir = makeProject();
    const result = makeResult([makeVuln()]);
    const savedPath = saveResults(dir, result);

    expect(fs.existsSync(savedPath)).toBe(true);
    expect(getResultsPath(dir)).toBe(savedPath);

    const loaded = loadResults(dir);
    expect(loaded).not.toBeNull();
    expect(loaded!.confirmedVulnerabilities).toHaveLength(1);
  });

  it("returns null when results don't exist", () => {
    const dir = makeProject();
    expect(loadResults(dir)).toBeNull();
  });

  it("returns null on corrupt results file", () => {
    const dir = makeProject();
    const p = getResultsPath(dir);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "not json {{{");
    expect(loadResults(dir)).toBeNull();
  });
});

describe("suppressions", () => {
  it("adds, loads, and removes a suppression", () => {
    const dir = makeProject();
    const vuln = makeVuln();

    addSuppression(dir, vuln, "known false positive");
    const loaded = loadSuppressions(dir);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].reason).toBe("known false positive");

    const removed = removeSuppression(dir, vuln.id);
    expect(removed).toBe(true);
    expect(loadSuppressions(dir)).toHaveLength(0);
  });

  it("does not add duplicate suppressions", () => {
    const dir = makeProject();
    const vuln = makeVuln();
    addSuppression(dir, vuln, "reason 1");
    addSuppression(dir, vuln, "reason 2");
    expect(loadSuppressions(dir)).toHaveLength(1);
  });

  it("returns false when removing an unknown suppression", () => {
    const dir = makeProject();
    expect(removeSuppression(dir, "does-not-exist")).toBe(false);
  });

  it("filters suppressed findings from scan output", () => {
    const dir = makeProject();
    const vuln = makeVuln();
    addSuppression(dir, vuln, "accepted risk");

    const { active, suppressed } = filterSuppressed([vuln], dir);
    expect(active).toHaveLength(0);
    expect(suppressed).toHaveLength(1);
  });

  it("honors inline // sphinx-ignore comments", () => {
    const dir = makeProject();
    const file = path.join(dir, "app.ts");
    fs.writeFileSync(
      file,
      [
        "// sphinx-ignore",
        "const dangerous = eval(userInput);", // line 2
      ].join("\n")
    );
    const vuln = makeVuln({
      location: { file: "app.ts", line: 2, snippet: "const dangerous = eval(userInput);" },
    });

    const { active, suppressed } = filterSuppressed([vuln], dir);
    expect(active).toHaveLength(0);
    expect(suppressed).toHaveLength(1);
  });

  it("honors .sphinxignore rule patterns", () => {
    const dir = makeProject();
    fs.writeFileSync(path.join(dir, ".sphinxignore"), "rule:sqli:sqli-template-literal\n");
    const vuln = makeVuln();

    const { active, suppressed } = filterSuppressed([vuln], dir);
    expect(active).toHaveLength(0);
    expect(suppressed).toHaveLength(1);
  });

  it("leaves unrelated findings active", () => {
    const dir = makeProject();
    const a = makeVuln({ id: "A" });
    const b = makeVuln({ id: "B", rule: "xss:xss-dom-innerhtml" });

    addSuppression(dir, a, "");
    const { active, suppressed } = filterSuppressed([a, b], dir);
    // 'a' is suppressed by file; 'b' stays active
    expect(active.map((f) => f.id)).toContain("B");
    expect(suppressed.map((f) => f.id)).toContain("A");
  });
});
