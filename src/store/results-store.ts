import fs from "node:fs";
import path from "node:path";
import type { ScanResult } from "../types/index.js";

const STORE_DIR = ".sphinx";
const RESULTS_FILE = "results.json";

export function saveResults(projectPath: string, result: ScanResult): string {
  const storeDir = path.join(projectPath, STORE_DIR);
  if (!fs.existsSync(storeDir)) {
    fs.mkdirSync(storeDir, { recursive: true });
  }

  const filePath = path.join(storeDir, RESULTS_FILE);
  fs.writeFileSync(filePath, JSON.stringify(result, null, 2), "utf-8");
  return filePath;
}

export function loadResults(projectPath: string): ScanResult | null {
  const filePath = path.join(projectPath, STORE_DIR, RESULTS_FILE);
  if (!fs.existsSync(filePath)) return null;

  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw) as ScanResult;
  } catch {
    return null;
  }
}

export function getResultsPath(projectPath: string): string {
  return path.join(projectPath, STORE_DIR, RESULTS_FILE);
}
