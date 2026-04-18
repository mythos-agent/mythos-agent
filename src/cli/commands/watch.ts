import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { loadConfig } from "../../config/config.js";
import { PatternScanner } from "../../scanner/pattern-scanner.js";
import { SecretsScanner } from "../../scanner/secrets-scanner.js";
import type { Vulnerability, Severity } from "../../types/index.js";

interface WatchOptions {
  severity: Severity;
  path?: string;
}

const SEVERITY_ICON: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

const DEBOUNCE_MS = 500;

export async function watchCommand(options: WatchOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);

  console.log(chalk.bold("\n👁️  shedu watch — Continuous Security Monitoring\n"));
  console.log(chalk.dim(`  Project: ${projectPath}`));
  console.log(chalk.dim(`  Severity: ${options.severity}+`));
  console.log(chalk.dim("  Press " + chalk.cyan("Ctrl+C") + " to stop.\n"));
  console.log(chalk.dim("─".repeat(50)) + "\n");

  const patternScanner = new PatternScanner(config);
  const secretsScanner = new SecretsScanner();

  // Track findings per file to detect new vs known
  const knownFindings = new Map<string, Set<string>>();

  // Debounce map
  const pending = new Map<string, NodeJS.Timeout>();

  // Watch for file changes
  const watcher = fs.watch(projectPath, { recursive: true }, (eventType, filename) => {
    if (!filename) return;
    const filePath = path.join(projectPath, filename);

    // Skip irrelevant files
    if (shouldIgnore(filename)) return;

    // Debounce
    const existing = pending.get(filePath);
    if (existing) clearTimeout(existing);

    pending.set(
      filePath,
      setTimeout(async () => {
        pending.delete(filePath);
        await scanFile(
          filePath,
          filename,
          projectPath,
          patternScanner,
          secretsScanner,
          config,
          knownFindings,
          options.severity
        );
      }, DEBOUNCE_MS)
    );
  });

  // Initial scan
  console.log(chalk.dim("  Running initial scan...\n"));
  const { findings } = await patternScanner.scan(projectPath);
  const { findings: secrets } = await secretsScanner.scan(projectPath);
  const allFindings = [...findings, ...secrets];

  // Populate known findings
  for (const f of allFindings) {
    const key = f.location.file;
    if (!knownFindings.has(key)) knownFindings.set(key, new Set());
    knownFindings.get(key)!.add(findingKey(f));
  }

  const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  const threshold = severityOrder.indexOf(options.severity);
  const filtered = allFindings.filter((f) => severityOrder.indexOf(f.severity) <= threshold);

  if (filtered.length > 0) {
    console.log(chalk.dim(`  Found ${filtered.length} existing issues. Watching for changes...\n`));
  } else {
    console.log(chalk.green("  ✅ No issues found. Watching for changes...\n"));
  }

  // Keep process alive
  process.on("SIGINT", () => {
    watcher.close();
    console.log(chalk.dim("\n\n  shedu watch stopped.\n"));
    process.exit(0);
  });
}

async function scanFile(
  absPath: string,
  relativePath: string,
  projectPath: string,
  patternScanner: PatternScanner,
  secretsScanner: SecretsScanner,
  config: any,
  knownFindings: Map<string, Set<string>>,
  severityThreshold: Severity
): Promise<void> {
  if (!fs.existsSync(absPath)) {
    // File deleted — clear its findings
    knownFindings.delete(relativePath);
    return;
  }

  // Run a quick scan on just this file (not the whole project)
  const tempConfig = { ...config, scan: { ...config.scan, include: [relativePath], exclude: [] } };
  const tempScanner = new PatternScanner(tempConfig);
  const { findings } = await tempScanner.scan(projectPath, false);
  // Secrets: filter to only the changed file instead of scanning everything
  const allFindings = [...findings].filter(
    (f) => f.location.file === relativePath.replace(/\\/g, "/") || f.location.file === relativePath
  );

  const known = knownFindings.get(relativePath) || new Set();
  const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  const threshold = severityOrder.indexOf(severityThreshold);

  // Find new issues
  const newFindings = allFindings.filter((f) => {
    if (severityOrder.indexOf(f.severity) > threshold) return false;
    return !known.has(findingKey(f));
  });

  // Find resolved issues
  const currentKeys = new Set(allFindings.map(findingKey));
  const resolved = [...known].filter((k) => !currentKeys.has(k));

  // Update known
  knownFindings.set(relativePath, new Set(allFindings.map(findingKey)));

  // Report new findings
  const timestamp = new Date().toLocaleTimeString();

  for (const f of newFindings) {
    const icon = SEVERITY_ICON[f.severity] || "⚪";
    console.log(
      chalk.dim(`  [${timestamp}]`) +
        ` ${icon} ` +
        chalk.bold(f.title) +
        chalk.dim(` — ${f.location.file}:${f.location.line}`)
    );
    if (f.location.snippet) {
      console.log(chalk.dim(`             > ${f.location.snippet}`));
    }
  }

  // Report resolved findings
  if (resolved.length > 0) {
    console.log(
      chalk.dim(`  [${timestamp}]`) +
        chalk.green(
          ` ✅ ${resolved.length} issue${resolved.length > 1 ? "s" : ""} resolved in ${relativePath}`
        )
    );
  }
}

function findingKey(f: Vulnerability): string {
  return `${f.rule}:${f.location.file}:${f.location.line}`;
}

function shouldIgnore(filename: string): boolean {
  const ignored = [
    "node_modules",
    ".git",
    "dist",
    "build",
    ".sphinx",
    ".next",
    "__pycache__",
    ".pyc",
    ".min.js",
    "package-lock.json",
    "yarn.lock",
  ];
  return ignored.some((i) => filename.includes(i));
}
