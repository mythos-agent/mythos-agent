import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";

interface MonitorOptions {
  path?: string;
  logFile?: string;
  format: string;
}

interface SecurityEvent {
  timestamp: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  source: string;
  line: number;
}

// Patterns that indicate runtime security events in logs
const LOG_PATTERNS: Array<{
  pattern: RegExp;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}> = [
  {
    pattern: /SQL\s*(?:syntax\s*)?error|ORA-\d+|PG::\w+Error/i,
    type: "sql-error",
    severity: "high",
    description: "Database error exposed — possible SQL injection attempt",
  },
  {
    pattern: /stack\s*trace|at\s+\w+\s+\(.*:\d+:\d+\)/i,
    type: "stack-trace",
    severity: "medium",
    description: "Stack trace exposed in output",
  },
  {
    pattern: /ECONNREFUSED|ETIMEDOUT.*(?:internal|169\.254|10\.|172\.(?:1[6-9]|2\d|3[01]))/i,
    type: "ssrf-attempt",
    severity: "high",
    description: "Connection to internal/metadata service — possible SSRF",
  },
  {
    pattern: /unauthorized|401.*(?:bearer|token|jwt)/i,
    type: "auth-failure",
    severity: "medium",
    description: "Authentication failure",
  },
  {
    pattern: /403.*forbidden|access\s*denied/i,
    type: "authz-failure",
    severity: "medium",
    description: "Authorization failure — access denied",
  },
  {
    pattern: /\.\.\/|\.\.\\|path\s*traversal|directory\s*traversal/i,
    type: "path-traversal",
    severity: "high",
    description: "Path traversal pattern in request",
  },
  {
    pattern: /<script|javascript:|on\w+\s*=|alert\s*\(/i,
    type: "xss-attempt",
    severity: "high",
    description: "Possible XSS payload in request",
  },
  {
    pattern: /rate\s*limit|too\s*many\s*requests|429/i,
    type: "rate-limit",
    severity: "low",
    description: "Rate limit triggered",
  },
  {
    pattern: /(?:password|secret|token|key)\s*[:=]\s*\S+/i,
    type: "secret-leak",
    severity: "critical",
    description: "Possible secret in log output",
  },
  {
    pattern: /segfault|SIGSEGV|buffer\s*overflow|heap\s*corruption/i,
    type: "memory-error",
    severity: "critical",
    description: "Memory safety error — possible exploitation",
  },
  {
    pattern: /exec|spawn|child_process.*(?:;|&&|\|\||`)/i,
    type: "cmd-injection",
    severity: "critical",
    description: "Possible command injection in execution",
  },
  {
    pattern: /deserializ|unmarshal|pickle\.load|readObject/i,
    type: "deserialization",
    severity: "high",
    description: "Deserialization of untrusted data",
  },
];

export async function monitorCommand(options: MonitorOptions) {
  console.log(chalk.bold("\n👁️  shedu monitor — Runtime Security Monitor\n"));

  if (options.logFile) {
    // Monitor a specific log file
    await monitorFile(options.logFile);
  } else {
    // Monitor stdin (pipe logs to shedu)
    console.log(chalk.dim("  Pipe your application logs:\n"));
    console.log(chalk.cyan("    your-app 2>&1 | shedu monitor"));
    console.log(chalk.cyan("    tail -f /var/log/app.log | shedu monitor"));
    console.log(chalk.dim("\n  Or specify a log file:\n"));
    console.log(chalk.cyan("    shedu monitor --log-file /var/log/app.log\n"));

    // Read from stdin
    console.log(chalk.dim("  Waiting for input...\n"));

    let lineNum = 0;
    let buffer = "";

    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk: string) => {
      buffer += chunk;
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        lineNum++;
        checkLine(line, lineNum, "stdin");
      }
    });

    process.stdin.on("end", () => {
      if (buffer.trim()) {
        lineNum++;
        checkLine(buffer, lineNum, "stdin");
      }
      console.log(chalk.dim(`\n  Processed ${lineNum} lines.\n`));
    });
  }
}

async function monitorFile(filePath: string) {
  const absPath = path.resolve(filePath);

  if (!fs.existsSync(absPath)) {
    console.log(chalk.yellow(`  ⚠️  File not found: ${absPath}\n`));
    return;
  }

  console.log(chalk.dim(`  Monitoring: ${absPath}`));
  console.log(chalk.dim("  Press Ctrl+C to stop.\n"));

  // Read existing content
  const content = fs.readFileSync(absPath, "utf-8");
  const lines = content.split("\n");
  let eventCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const found = checkLine(lines[i], i + 1, filePath);
    if (found) eventCount++;
  }

  if (eventCount > 0) {
    console.log(chalk.dim(`\n  Found ${eventCount} security event(s) in existing log.\n`));
  }

  // Watch for new lines
  let lastSize = fs.statSync(absPath).size;

  fs.watch(absPath, () => {
    const newSize = fs.statSync(absPath).size;
    if (newSize <= lastSize) return;

    const fd = fs.openSync(absPath, "r");
    const buffer = Buffer.alloc(newSize - lastSize);
    fs.readSync(fd, buffer, 0, buffer.length, lastSize);
    fs.closeSync(fd);
    lastSize = newSize;

    const newLines = buffer.toString("utf-8").split("\n");
    // Count total lines in file for approximate line number
    const existingLines = fs.readFileSync(absPath, "utf-8").split("\n").length;
    for (let i = 0; i < newLines.length; i++) {
      if (newLines[i].trim()) checkLine(newLines[i], existingLines - newLines.length + i, filePath);
    }
  });
}

function checkLine(line: string, lineNum: number, source: string): boolean {
  for (const p of LOG_PATTERNS) {
    if (p.pattern.test(line)) {
      const timestamp = new Date().toLocaleTimeString();
      const color =
        p.severity === "critical"
          ? chalk.red
          : p.severity === "high"
            ? chalk.yellow
            : p.severity === "medium"
              ? chalk.blue
              : chalk.dim;

      console.log(
        chalk.dim(`  [${timestamp}]`) +
          ` ${color(`[${p.severity.toUpperCase()}]`)} ` +
          chalk.bold(p.type) +
          chalk.dim(` — ${p.description}`)
      );
      console.log(chalk.dim(`    ${line.trim().slice(0, 120)}`));
      return true;
    }
  }
  return false;
}
