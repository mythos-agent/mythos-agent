import fs from "node:fs";
import path from "node:path";
import type { Vulnerability } from "../types/index.js";

interface Suppression {
  id: string;
  rule: string;
  file: string;
  line: number;
  reason: string;
  suppressedAt: string;
  suppressedBy?: string;
}

interface SuppressionData {
  version: number;
  suppressions: Suppression[];
}

const SUPPRESSION_FILE = ".sphinx/suppressions.json";

export function loadSuppressions(projectPath: string): Suppression[] {
  const filePath = path.join(projectPath, SUPPRESSION_FILE);
  if (!fs.existsSync(filePath)) return [];

  try {
    const data = JSON.parse(fs.readFileSync(filePath, "utf-8")) as SuppressionData;
    return data.suppressions || [];
  } catch {
    return [];
  }
}

export function addSuppression(
  projectPath: string,
  vuln: Vulnerability,
  reason: string
): void {
  const suppressions = loadSuppressions(projectPath);

  // Don't add duplicate
  if (suppressions.some((s) => s.id === vuln.id && s.file === vuln.location.file)) {
    return;
  }

  suppressions.push({
    id: vuln.id,
    rule: vuln.rule,
    file: vuln.location.file,
    line: vuln.location.line,
    reason,
    suppressedAt: new Date().toISOString(),
  });

  saveSuppressions(projectPath, suppressions);
}

export function removeSuppression(
  projectPath: string,
  findingId: string
): boolean {
  const suppressions = loadSuppressions(projectPath);
  const filtered = suppressions.filter((s) => s.id !== findingId);
  if (filtered.length === suppressions.length) return false;
  saveSuppressions(projectPath, filtered);
  return true;
}

/**
 * Filter out suppressed findings from scan results.
 * Checks both .sphinx/suppressions.json and inline // sphinx-ignore comments.
 */
export function filterSuppressed(
  findings: Vulnerability[],
  projectPath: string
): { active: Vulnerability[]; suppressed: Vulnerability[] } {
  const suppressions = loadSuppressions(projectPath);
  // Include line group in key so suppressing one finding doesn't silence
  // unrelated matches of the same rule in the same file
  const suppressionKeys = new Set(
    suppressions.map((s) => `${s.rule}:${s.file}:${Math.floor(s.line / 5) * 5}`)
  );

  const active: Vulnerability[] = [];
  const suppressed: Vulnerability[] = [];

  for (const f of findings) {
    const key = `${f.rule}:${f.location.file}:${Math.floor(f.location.line / 5) * 5}`;

    // Check suppression file
    if (suppressionKeys.has(key)) {
      suppressed.push(f);
      continue;
    }

    // Check inline comment (// sphinx-ignore or # sphinx-ignore)
    if (hasInlineIgnore(f, projectPath)) {
      suppressed.push(f);
      continue;
    }

    // Check .sphinxignore file patterns
    if (isIgnoredByFile(f, projectPath)) {
      suppressed.push(f);
      continue;
    }

    active.push(f);
  }

  return { active, suppressed };
}

function hasInlineIgnore(
  vuln: Vulnerability,
  projectPath: string
): boolean {
  const absPath = path.resolve(projectPath, vuln.location.file);
  if (!fs.existsSync(absPath)) return false;

  try {
    const lines = fs.readFileSync(absPath, "utf-8").split("\n");
    const lineIdx = vuln.location.line - 1;

    // Check the line above for sphinx-ignore comment
    if (lineIdx > 0) {
      const prevLine = lines[lineIdx - 1].trim();
      if (prevLine.includes("sphinx-ignore")) {
        // Check if it targets a specific rule
        if (prevLine.includes(vuln.rule) || !prevLine.includes(":")) {
          return true;
        }
      }
    }

    // Check inline comment on the same line
    const currentLine = lines[lineIdx];
    if (currentLine && currentLine.includes("sphinx-ignore")) {
      return true;
    }
  } catch {
    // file read error
  }

  return false;
}

function isIgnoredByFile(
  vuln: Vulnerability,
  projectPath: string
): boolean {
  const ignorePath = path.join(projectPath, ".sphinxignore");
  if (!fs.existsSync(ignorePath)) return false;

  try {
    const patterns = fs
      .readFileSync(ignorePath, "utf-8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));

    for (const pattern of patterns) {
      // Rule-based ignore: "rule:sql-injection"
      if (pattern.startsWith("rule:")) {
        const rulePattern = pattern.slice(5);
        if (vuln.rule === rulePattern || vuln.rule.includes(rulePattern)) {
          return true;
        }
      }

      // File-based ignore: "src/tests/**"
      if (vuln.location.file.includes(pattern.replace("**", "").replace("*", ""))) {
        return true;
      }

      // Category-based ignore: "category:info"
      if (pattern.startsWith("category:")) {
        if (vuln.category === pattern.slice(9)) return true;
      }

      // Severity-based ignore: "severity:low"
      if (pattern.startsWith("severity:")) {
        if (vuln.severity === pattern.slice(9)) return true;
      }
    }
  } catch {
    // file read error
  }

  return false;
}

function saveSuppressions(
  projectPath: string,
  suppressions: Suppression[]
): void {
  const filePath = path.join(projectPath, SUPPRESSION_FILE);
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const data: SuppressionData = { version: 1, suppressions };
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}
