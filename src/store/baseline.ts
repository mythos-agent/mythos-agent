import fs from "node:fs";
import path from "node:path";
import type { Vulnerability, ScanResult } from "../types/index.js";

interface BaselineData {
  version: number;
  timestamp: string;
  findings: BaselineFinding[];
}

interface BaselineFinding {
  rule: string;
  file: string;
  line: number;
  severity: string;
  title: string;
  fingerprint: string;
}

export interface BaselineDiff {
  newFindings: Vulnerability[];
  fixedFindings: BaselineFinding[];
  unchangedCount: number;
}

const BASELINE_FILE = ".sphinx/baseline.json";

/**
 * Save current scan results as the baseline for future comparison.
 */
export function saveBaseline(projectPath: string, result: ScanResult): string {
  const baselinePath = path.join(projectPath, BASELINE_FILE);
  const dir = path.dirname(baselinePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const data: BaselineData = {
    version: 1,
    timestamp: result.timestamp,
    findings: result.confirmedVulnerabilities.map(vulnToBaseline),
  };

  fs.writeFileSync(baselinePath, JSON.stringify(data, null, 2), "utf-8");
  return baselinePath;
}

/**
 * Load the saved baseline.
 */
export function loadBaseline(projectPath: string): BaselineData | null {
  const baselinePath = path.join(projectPath, BASELINE_FILE);
  if (!fs.existsSync(baselinePath)) return null;

  try {
    const raw = fs.readFileSync(baselinePath, "utf-8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Compare current scan results against the saved baseline.
 * Returns new findings (regressions) and fixed findings (improvements).
 */
export function compareToBaseline(projectPath: string, current: ScanResult): BaselineDiff | null {
  const baseline = loadBaseline(projectPath);
  if (!baseline) return null;

  const baselineFingerprints = new Set(baseline.findings.map((f) => f.fingerprint));

  const currentFingerprints = new Map<string, Vulnerability>();
  for (const v of current.confirmedVulnerabilities) {
    currentFingerprints.set(fingerprint(v), v);
  }

  // New: in current but not in baseline
  const newFindings: Vulnerability[] = [];
  for (const [fp, vuln] of currentFingerprints) {
    if (!baselineFingerprints.has(fp)) {
      newFindings.push(vuln);
    }
  }

  // Fixed: in baseline but not in current
  const fixedFindings: BaselineFinding[] = [];
  for (const bf of baseline.findings) {
    if (!currentFingerprints.has(bf.fingerprint)) {
      fixedFindings.push(bf);
    }
  }

  const unchangedCount = current.confirmedVulnerabilities.length - newFindings.length;

  return { newFindings, fixedFindings, unchangedCount };
}

function vulnToBaseline(v: Vulnerability): BaselineFinding {
  return {
    rule: v.rule,
    file: v.location.file,
    line: v.location.line,
    severity: v.severity,
    title: v.title,
    fingerprint: fingerprint(v),
  };
}

function fingerprint(v: Vulnerability): string {
  // Stable fingerprint: rule + file + nearby line (allow small shifts)
  const lineGroup = Math.floor(v.location.line / 5) * 5;
  return `${v.rule}:${v.location.file}:${lineGroup}`;
}
