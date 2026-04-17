import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface ErrorRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}

const ERROR_RULES: ErrorRule[] = [
  {
    id: "error-empty-catch",
    title: "Error Handling: Empty Catch Block",
    description:
      "Catch block is empty or only has a comment. Swallowed errors hide bugs and security issues.",
    severity: "medium",
    cwe: "CWE-390",
    patterns: [
      /catch\s*\([^)]*\)\s*\{\s*\}/gi,
      /catch\s*\([^)]*\)\s*\{\s*\/\/.*\s*\}/gi,
      /except\s*(?:\w+)?:\s*\n\s*pass/gi,
    ],
  },
  {
    id: "error-stack-exposure",
    title: "Error Handling: Stack Trace Exposed to Users",
    description:
      "Error stack trace sent in API response. This leaks internal paths, library versions, and code structure.",
    severity: "high",
    cwe: "CWE-209",
    patterns: [
      /res\.(?:json|send)\s*\(.*(?:err\.stack|error\.stack|\.stack)/gi,
      /res\.status\s*\(\s*500\s*\).*(?:stack|stackTrace|trace)/gi,
      /traceback\.format_exc\s*\(\)/gi,
    ],
  },
  {
    id: "error-verbose-message",
    title: "Error Handling: Verbose Error Message in Response",
    description:
      "Detailed error message sent to client. Error messages may reveal database schema, file paths, or internal logic.",
    severity: "medium",
    cwe: "CWE-209",
    patterns: [
      /res\.(?:json|send)\s*\(\s*\{\s*(?:error|message)\s*:\s*(?:err|error)\.message/gi,
      /res\.status\s*\(\s*\d{3}\s*\)\.(?:json|send)\s*\(\s*(?:err|error)\s*\)/gi,
    ],
  },
  {
    id: "error-generic-catch",
    title: "Error Handling: Catching All Exceptions",
    description:
      "Broad catch-all exception handling may mask security-relevant errors like auth failures or injection attempts.",
    severity: "low",
    cwe: "CWE-396",
    patterns: [
      /catch\s*\(\s*(?:e|err|error|ex|exception)\s*\)\s*\{[\s\S]{0,20}(?:console\.log|\/\/)/gi,
      /except\s+Exception\s*(?:as)?\s*\w*\s*:/gi,
    ],
  },
  {
    id: "error-no-error-handler",
    title: "Error Handling: No Global Error Handler",
    description:
      "Express app without error-handling middleware. Unhandled errors may crash the server or leak information.",
    severity: "medium",
    cwe: "CWE-755",
    patterns: [
      /app\.listen\s*\((?![\s\S]{0,500}(?:app\.use\s*\(\s*\(\s*err|process\.on\s*\(\s*['"]uncaughtException))/gi,
    ],
  },
  {
    id: "error-unhandled-rejection",
    title: "Error Handling: No Unhandled Promise Rejection Handler",
    description:
      "No handler for unhandledRejection event. Unhandled promise rejections can crash Node.js.",
    severity: "medium",
    cwe: "CWE-755",
    patterns: [/app\.listen\s*\((?![\s\S]{0,500}process\.on\s*\(\s*['"]unhandledRejection)/gi],
  },
  {
    id: "error-debug-in-prod",
    title: "Error Handling: Debug/Development Error Page in Production",
    description: "Debug error pages or detailed error rendering enabled without environment check.",
    severity: "high",
    cwe: "CWE-215",
    patterns: [
      /app\.use\s*\(\s*(?:errorHandler|devErrorHandler)\s*\(\s*\)\s*\)(?!.*(?:NODE_ENV|production|isProduction))/gi,
      /DEBUG\s*=\s*True(?!.*(?:if|environ|config|settings))/gi,
    ],
  },
  {
    id: "error-info-leak-header",
    title: "Error Handling: Server Version in Response Headers",
    description:
      "Server software and version exposed via headers (X-Powered-By, Server). Remove these in production.",
    severity: "low",
    cwe: "CWE-200",
    patterns: [
      /res\.setHeader\s*\(\s*['"]X-Powered-By['"]/gi,
      /res\.setHeader\s*\(\s*['"]Server['"].*(?:express|node|nginx|apache)/gi,
    ],
  },
];

export interface ErrorHandlingScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class ErrorHandlingScanner {
  async scan(projectPath: string): Promise<ErrorHandlingScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
      nodir: true,
    });

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of ERROR_RULES) {
        for (const pattern of rule.patterns) {
          // Some patterns need multi-line matching
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(content)) !== null) {
            const lineNum = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `ERR-${String(idCounter++).padStart(4, "0")}`,
              rule: `error:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "error-handling",
              cwe: rule.cwe,
              confidence: "medium",
              location: {
                file: relativePath,
                line: lineNum,
                snippet: lines[lineNum - 1]?.trim() || "",
              },
            });
            break; // One per rule per file
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
