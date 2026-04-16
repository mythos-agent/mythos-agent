import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const REDIRECT_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "redirect-user-input",
    title: "Redirect: User Input in Redirect URL",
    description: "Redirect destination from user input without validation. Attacker redirects users to phishing sites after login.",
    severity: "medium",
    cwe: "CWE-601",
    patterns: [
      /res\.redirect\s*\(\s*(?:req\.query\.|req\.body\.|req\.params\.|input|url|next|return|callback|redirect)/gi,
      /redirect\s*\(\s*request\.(?:args|form|values)\.get\s*\(\s*['"](?:next|url|redirect|return|callback)/gi,
      /http\.Redirect\s*\(.*(?:r\.URL\.Query|r\.FormValue)/gi,
    ],
  },
  {
    id: "redirect-protocol-relative",
    title: "Redirect: Protocol-Relative URL Not Blocked",
    description: "Redirect allows protocol-relative URLs (//evil.com). These redirect to external sites while bypassing domain checks.",
    severity: "medium",
    cwe: "CWE-601",
    patterns: [
      /redirect.*(?:url|next|return)(?![\s\S]{0,100}(?:startsWith\s*\(\s*['"]\/[^\/]|protocol|hostname|whitelist|allowlist))/gi,
    ],
  },
  {
    id: "redirect-header-injection",
    title: "Redirect: Location Header with User Input",
    description: "Setting Location header with user input. Can enable header injection if newlines aren't stripped.",
    severity: "high",
    cwe: "CWE-113",
    patterns: [
      /(?:setHeader|set)\s*\(\s*['"]Location['"]\s*,\s*(?:req\.|input|url|next|redirect)/gi,
      /Location\s*[:=]\s*(?:req\.|input|data|params)/gi,
    ],
  },
  {
    id: "redirect-meta-refresh",
    title: "Redirect: Meta Refresh with User Input",
    description: "HTML meta refresh tag with user-controlled URL. Same impact as server-side open redirect.",
    severity: "medium",
    cwe: "CWE-601",
    patterns: [
      /meta.*http-equiv.*refresh.*content.*(?:req\.|input|url|data|\$\{)/gi,
      /window\.location\s*=\s*(?:req\.|input|params|query|data)/gi,
    ],
  },
];

export interface OpenRedirectScanResult { findings: Vulnerability[]; filesScanned: number; }

export class OpenRedirectScanner {
  async scan(projectPath: string): Promise<OpenRedirectScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py", "**/*.go"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/redirect|location|window\.location|meta.*refresh/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of REDIRECT_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `REDIR-${String(id++).padStart(4, "0")}`, rule: `redirect:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "open-redirect", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
