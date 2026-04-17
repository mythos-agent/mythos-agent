import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const SUB_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "sub-wildcard-cors",
    title: "Subdomain: Wildcard Subdomain in CORS",
    description:
      "CORS allows *.example.com. Any subdomain (including attacker-controlled ones) can access the API.",
    severity: "high",
    cwe: "CWE-942",
    patterns: [/origin.*\*\.\w+\.\w+/gi, /allowedOrigins.*\*\.\w+\.\w+/gi],
  },
  {
    id: "sub-cookie-parent-domain",
    title: "Subdomain: Cookie Domain Set to Parent",
    description:
      "Cookie domain set to parent domain (.example.com). All subdomains can read this cookie, including compromised ones.",
    severity: "medium",
    cwe: "CWE-1275",
    patterns: [/domain\s*[:=]\s*['"]\.(?!localhost)\w+\.\w+['"]/gi],
  },
  {
    id: "sub-postmessage-no-origin",
    title: "Subdomain: postMessage Without Origin Check",
    description:
      "postMessage listener without validating event.origin. Any page (including from other subdomains) can send messages.",
    severity: "high",
    cwe: "CWE-345",
    patterns: [
      /addEventListener\s*\(\s*['"]message['"][\s\S]{0,100}(?!.*(?:origin|source))/gi,
      /onmessage\s*=(?![\s\S]{0,100}(?:origin|source))/gi,
    ],
  },
];

export interface SubdomainScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class SubdomainScanner {
  async scan(projectPath: string): Promise<SubdomainScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
      nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try {
        const s = fs.statSync(file);
        if (s.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }
      if (!/domain|postMessage|message|origin|cookie/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of SUB_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `SUB-${String(id++).padStart(4, "0")}`,
              rule: `sub:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "subdomain",
              cwe: rule.cwe,
              confidence: "medium",
              location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" },
            });
            break;
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
