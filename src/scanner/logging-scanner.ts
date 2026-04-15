import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const LOG_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "log-injection",
    title: "Logging: Log Injection",
    description: "User input logged without sanitization. Attackers can inject fake log entries, break log parsing, or exploit log viewers.",
    severity: "medium",
    cwe: "CWE-117",
    patterns: [
      /(?:console\.log|logger\.\w+|log\.\w+)\s*\(\s*(?:`[^`]*\$\{req\.|.*\+\s*req\.)/gi,
      /logging\.(?:info|warning|error|debug)\s*\(\s*f["'].*\{(?:request|input|user)/gi,
    ],
  },
  {
    id: "log-sensitive-data",
    title: "Logging: Sensitive Data in Logs",
    description: "Passwords, tokens, or secrets may be written to logs. Redact sensitive fields before logging.",
    severity: "high",
    cwe: "CWE-532",
    patterns: [
      /(?:console\.log|logger\.\w+)\s*\(.*(?:password|passwd|secret|token|apiKey|authorization|creditCard|ssn)/gi,
    ],
  },
  {
    id: "log-no-security-events",
    title: "Logging: No Security Event Logging",
    description: "Authentication or authorization events not logged. Security monitoring requires logging login attempts, access denials, and privilege changes.",
    severity: "medium",
    cwe: "CWE-778",
    patterns: [
      /(?:login|authenticate|signIn)\s*(?:=|async)(?![\s\S]{0,500}(?:log|audit|event|track|record))/gi,
    ],
  },
  {
    id: "log-error-details-exposed",
    title: "Logging: Internal Error Details in User Response",
    description: "Internal error details (file paths, SQL, stack) sent to user AND logged. Log details internally, send generic message to user.",
    severity: "medium",
    cwe: "CWE-209",
    patterns: [
      /catch\s*\([^)]*\)\s*\{[\s\S]{0,100}res\.(?:json|send)\s*\(\s*\{.*(?:err|error)\.\w+/gi,
    ],
  },
  {
    id: "log-console-in-prod",
    title: "Logging: console.log in Production Code",
    description: "console.log used for logging in production. Use a structured logger (winston, pino, bunyan) with log levels.",
    severity: "low",
    cwe: "CWE-778",
    patterns: [
      /console\.log\s*\(\s*(?!.*(?:test|debug|TODO|FIXME))/gi,
    ],
  },
];

export interface LoggingScanResult { findings: Vulnerability[]; filesScanned: number; }

export class LoggingScanner {
  async scan(projectPath: string): Promise<LoggingScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of LOG_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `LOG-${String(id++).padStart(4, "0")}`, rule: `log:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "logging", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
