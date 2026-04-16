import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const CJ_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "cj-iframe-allow",
    title: "Clickjacking: Page Embeddable in Iframe",
    description: "No X-Frame-Options or frame-ancestors CSP. Page can be embedded in malicious iframes for clickjacking.",
    severity: "medium",
    cwe: "CWE-1021",
    patterns: [
      /(?:app|server)\.(?:get|use)\s*\((?![\s\S]{0,500}(?:X-Frame-Options|frame-ancestors|helmet))/gi,
    ],
  },
  {
    id: "cj-sandbox-bypass",
    title: "Clickjacking: Sandbox Attribute Missing allow-scripts",
    description: "Iframe sandbox without proper restrictions may still allow script execution or form submission.",
    severity: "low",
    cwe: "CWE-1021",
    patterns: [
      /sandbox\s*=\s*["'][^"']*allow-(?:scripts|forms|same-origin)[^"']*["']/gi,
    ],
  },
  {
    id: "cj-window-opener",
    title: "Clickjacking: window.open Without noopener",
    description: "Links opening new windows without rel='noopener' allow the new page to navigate the opener via window.opener.",
    severity: "medium",
    cwe: "CWE-1022",
    patterns: [
      /window\.open\s*\((?![\s\S]{0,100}noopener)/gi,
      /target\s*=\s*["']_blank["'](?![\s\S]{0,50}(?:noopener|noreferrer))/gi,
    ],
  },
];

export interface ClickjackingScanResult { findings: Vulnerability[]; filesScanned: number; }

export class ClickjackingScanner {
  async scan(projectPath: string): Promise<ClickjackingScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.html"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/iframe|frame|window\.open|target.*_blank|sandbox/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of CJ_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({ id: `CJ-${String(id++).padStart(4, "0")}`, rule: `cj:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "clickjacking", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" } });
            break;
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
