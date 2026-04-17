import fs from "node:fs";
import path from "node:path";
import type { ScanResult } from "../types/index.js";

interface HistoryEntry {
  timestamp: string;
  duration: number;
  filesScanned: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  chains: number;
  dismissed: number;
  trustScore: number;
}

interface HistoryData {
  version: number;
  scans: HistoryEntry[];
}

const HISTORY_FILE = ".sphinx/history.json";
const MAX_ENTRIES = 100;

/**
 * Record a scan result in the history.
 */
export function recordScan(projectPath: string, result: ScanResult): void {
  const history = loadHistory(projectPath);
  const vulns = result.confirmedVulnerabilities;

  let trustScore = 10;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        trustScore -= 2;
        break;
      case "high":
        trustScore -= 1;
        break;
      case "medium":
        trustScore -= 0.5;
        break;
      case "low":
        trustScore -= 0.2;
        break;
    }
  }
  trustScore = Math.max(0, Math.min(10, trustScore));

  history.scans.push({
    timestamp: result.timestamp,
    duration: result.duration,
    filesScanned: result.filesScanned,
    total: vulns.length,
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
    chains: result.chains.length,
    dismissed: result.dismissedCount,
    trustScore,
  });

  // Trim to max entries
  if (history.scans.length > MAX_ENTRIES) {
    history.scans = history.scans.slice(-MAX_ENTRIES);
  }

  saveHistory(projectPath, history);
}

/**
 * Load scan history.
 */
export function loadHistory(projectPath: string): HistoryData {
  const filePath = path.join(projectPath, HISTORY_FILE);
  if (!fs.existsSync(filePath)) return { version: 1, scans: [] };

  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return { version: 1, scans: [] };
  }
}

/**
 * Get trend data for the dashboard.
 */
export function getTrends(
  projectPath: string,
  last = 30
): {
  dates: string[];
  totals: number[];
  trustScores: number[];
  criticals: number[];
} {
  const history = loadHistory(projectPath);
  const recent = history.scans.slice(-last);

  return {
    dates: recent.map((s) => new Date(s.timestamp).toLocaleDateString()),
    totals: recent.map((s) => s.total),
    trustScores: recent.map((s) => s.trustScore),
    criticals: recent.map((s) => s.critical),
  };
}

function saveHistory(projectPath: string, data: HistoryData): void {
  const filePath = path.join(projectPath, HISTORY_FILE);
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}
