import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface HeaderRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  missingPatterns: RegExp[];
  presentPatterns?: RegExp[];
  checkType: "missing" | "misconfigured";
}

const HEADER_RULES: HeaderRule[] = [
  {
    id: "header-no-csp",
    title: "Headers: Missing Content-Security-Policy",
    description:
      "No Content-Security-Policy header found. CSP prevents XSS, clickjacking, and data injection attacks.",
    severity: "high",
    cwe: "CWE-693",
    missingPatterns: [/Content-Security-Policy/gi],
    checkType: "missing",
  },
  {
    id: "header-csp-unsafe",
    title: "Headers: CSP with unsafe-inline or unsafe-eval",
    description:
      "CSP allows unsafe-inline or unsafe-eval, which significantly weakens XSS protection.",
    severity: "high",
    cwe: "CWE-693",
    missingPatterns: [],
    presentPatterns: [/Content-Security-Policy.*(?:unsafe-inline|unsafe-eval)/gi],
    checkType: "misconfigured",
  },
  {
    id: "header-no-hsts",
    title: "Headers: Missing Strict-Transport-Security (HSTS)",
    description:
      "No HSTS header. Browsers may connect via HTTP, enabling man-in-the-middle attacks.",
    severity: "medium",
    cwe: "CWE-319",
    missingPatterns: [/Strict-Transport-Security/gi],
    checkType: "missing",
  },
  {
    id: "header-no-xframe",
    title: "Headers: Missing X-Frame-Options",
    description:
      "No X-Frame-Options header. Pages can be embedded in iframes, enabling clickjacking attacks.",
    severity: "medium",
    cwe: "CWE-1021",
    missingPatterns: [/X-Frame-Options/gi],
    checkType: "missing",
  },
  {
    id: "header-no-xcontent-type",
    title: "Headers: Missing X-Content-Type-Options",
    description:
      "No X-Content-Type-Options: nosniff header. Browsers may MIME-sniff responses, enabling XSS via file uploads.",
    severity: "medium",
    cwe: "CWE-693",
    missingPatterns: [/X-Content-Type-Options/gi],
    checkType: "missing",
  },
  {
    id: "header-no-referrer-policy",
    title: "Headers: Missing Referrer-Policy",
    description:
      "No Referrer-Policy header. Sensitive URL parameters may leak to external sites via the Referer header.",
    severity: "low",
    cwe: "CWE-200",
    missingPatterns: [/Referrer-Policy/gi],
    checkType: "missing",
  },
  {
    id: "header-no-permissions-policy",
    title: "Headers: Missing Permissions-Policy",
    description:
      "No Permissions-Policy header. Third-party scripts can access camera, microphone, and geolocation.",
    severity: "low",
    cwe: "CWE-693",
    missingPatterns: [/Permissions-Policy|Feature-Policy/gi],
    checkType: "missing",
  },
  {
    id: "header-x-powered-by",
    title: "Headers: X-Powered-By Exposed",
    description:
      "X-Powered-By header reveals server technology. Remove it to prevent information disclosure.",
    severity: "low",
    cwe: "CWE-200",
    missingPatterns: [],
    presentPatterns: [/X-Powered-By/gi],
    checkType: "misconfigured",
  },
];

export interface HeadersScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class HeadersScanner {
  async scan(projectPath: string): Promise<HeadersScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
      nodir: true,
    });

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    // Collect all security header references across the codebase
    let allContent = "";
    const serverFiles: string[] = [];

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      // Only check files that set up HTTP servers
      if (
        /(?:express|fastify|koa|hono|app\.|server\.|createServer|helmet|Flask|Django)/i.test(
          content
        )
      ) {
        allContent += content + "\n";
        serverFiles.push(path.relative(projectPath, file));
      }
    }

    if (serverFiles.length === 0) return { findings: [], filesScanned: files.length };

    // Check for missing headers across all server files
    for (const rule of HEADER_RULES) {
      if (rule.checkType === "missing") {
        const found = rule.missingPatterns.some((p) => {
          p.lastIndex = 0;
          return p.test(allContent);
        });
        // Also check if helmet is used (sets most headers)
        const hasHelmet = /helmet/i.test(allContent);

        if (!found && !hasHelmet) {
          findings.push({
            id: `HDR-${String(idCounter++).padStart(4, "0")}`,
            rule: `headers:${rule.id}`,
            title: rule.title,
            description: rule.description,
            severity: rule.severity,
            category: "headers",
            cwe: rule.cwe,
            confidence: "medium",
            location: {
              file: serverFiles[0],
              line: 0,
              snippet: `No ${rule.missingPatterns[0]?.source || "header"} found in server files`,
            },
          });
        }
      } else if (rule.checkType === "misconfigured" && rule.presentPatterns) {
        for (const pattern of rule.presentPatterns) {
          pattern.lastIndex = 0;
          if (pattern.test(allContent)) {
            // Find which file has it
            for (const serverFile of serverFiles) {
              const absPath = path.join(projectPath, serverFile);
              const content = fs.readFileSync(absPath, "utf-8");
              const lines = content.split("\n");
              for (let i = 0; i < lines.length; i++) {
                pattern.lastIndex = 0;
                if (pattern.test(lines[i])) {
                  findings.push({
                    id: `HDR-${String(idCounter++).padStart(4, "0")}`,
                    rule: `headers:${rule.id}`,
                    title: rule.title,
                    description: rule.description,
                    severity: rule.severity,
                    category: "headers",
                    cwe: rule.cwe,
                    confidence: "high",
                    location: {
                      file: serverFile,
                      line: i + 1,
                      snippet: lines[i].trim(),
                    },
                  });
                  break;
                }
              }
            }
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
