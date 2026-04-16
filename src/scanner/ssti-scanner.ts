import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const SSTI_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "ssti-jinja2",
    title: "SSTI: Jinja2 Template with User Input",
    description: "User input passed to Jinja2 Template() or render_template_string(). Enables server-side code execution.",
    severity: "critical",
    cwe: "CWE-1336",
    patterns: [
      /Template\s*\(\s*(?:request|input|data|user|query|form)/gi,
      /render_template_string\s*\(\s*(?:request|input|data|user|form)/gi,
      /Environment\s*\([\s\S]*?\.from_string\s*\(\s*(?:request|input|data)/gi,
    ],
  },
  {
    id: "ssti-ejs",
    title: "SSTI: EJS Template with User Input",
    description: "User input in EJS render. Use <%- for escaped output, never pass user input as template string.",
    severity: "critical",
    cwe: "CWE-1336",
    patterns: [
      /ejs\.render\s*\(\s*(?:req|input|data|body|query)/gi,
      /ejs\.compile\s*\(\s*(?:req|input|data|body)/gi,
      /res\.render\s*\(\s*(?:req\.body|req\.query|req\.params)\./gi,
    ],
  },
  {
    id: "ssti-handlebars",
    title: "SSTI: Handlebars Template with User Input",
    description: "User input compiled as Handlebars template. Use precompiled templates with data context instead.",
    severity: "critical",
    cwe: "CWE-1336",
    patterns: [
      /Handlebars\.compile\s*\(\s*(?:req|input|data|body|user)/gi,
      /hbs\.compile\s*\(\s*(?:req|input|data)/gi,
    ],
  },
  {
    id: "ssti-pug",
    title: "SSTI: Pug/Jade Template with User Input",
    description: "User input in Pug template compilation. Pug templates can execute arbitrary JavaScript.",
    severity: "critical",
    cwe: "CWE-1336",
    patterns: [
      /pug\.compile\s*\(\s*(?:req|input|data|body)/gi,
      /pug\.render\s*\(\s*(?:req|input|data|body)/gi,
      /jade\.compile\s*\(\s*(?:req|input|data)/gi,
    ],
  },
  {
    id: "ssti-nunjucks",
    title: "SSTI: Nunjucks Template with User Input",
    description: "User input passed to Nunjucks renderString(). Enables template injection.",
    severity: "critical",
    cwe: "CWE-1336",
    patterns: [
      /nunjucks\.renderString\s*\(\s*(?:req|input|data|body|user)/gi,
    ],
  },
  {
    id: "ssti-twig",
    title: "SSTI: Twig Template with User Input (PHP)",
    description: "User input in Twig template creation. Use Twig's auto-escaping and never create templates from user input.",
    severity: "critical",
    cwe: "CWE-1336",
    patterns: [
      /createTemplate\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      /Twig.*Environment.*loadTemplate.*\$_(?:GET|POST|REQUEST)/gi,
    ],
  },
  {
    id: "ssti-go-template",
    title: "SSTI: Go Template with User Input",
    description: "User input parsed as Go template. template.New().Parse() with user input enables code execution.",
    severity: "critical",
    cwe: "CWE-1336",
    patterns: [
      /template\.(?:New|Must)\s*\(\s*\w+\s*\)\.Parse\s*\(\s*(?:r\.|req\.|input|data|user)/gi,
    ],
  },
];

export interface SstiScanResult { findings: Vulnerability[]; filesScanned: number; }

export class SstiScanner {
  async scan(projectPath: string): Promise<SstiScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.php"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/template|render|compile|jinja|ejs|handlebars|pug|jade|nunjucks|twig/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of SSTI_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `SSTI-${String(id++).padStart(4, "0")}`, rule: `ssti:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "ssti", cwe: rule.cwe, confidence: "high", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
