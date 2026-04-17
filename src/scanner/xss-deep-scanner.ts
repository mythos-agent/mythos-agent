import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const XSS_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "xss-dom-innerhtml",
    title: "XSS: innerHTML with User Input",
    description:
      "User-controlled data assigned to innerHTML. Use textContent or a sanitizer like DOMPurify.",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /\.innerHTML\s*=\s*(?:.*(?:req|input|user|data|query|params|search|hash|location)|`[^`]*\$\{)/gi,
    ],
  },
  {
    id: "xss-dom-document-write",
    title: "XSS: document.write with Dynamic Content",
    description:
      "document.write() with user input enables DOM XSS. Use DOM APIs (createElement, textContent) instead.",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /document\.write\s*\(\s*(?:.*(?:location|search|hash|referrer|input|user)|`[^`]*\$\{)/gi,
    ],
  },
  {
    id: "xss-react-dangerously",
    title: "XSS: React dangerouslySetInnerHTML",
    description:
      "dangerouslySetInnerHTML renders raw HTML. If the content includes user input, XSS is possible.",
    severity: "high",
    cwe: "CWE-79",
    patterns: [/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/gi],
  },
  {
    id: "xss-href-javascript",
    title: "XSS: javascript: Protocol in href",
    description:
      "User input in href can execute JavaScript via javascript: protocol. Validate URLs start with http(s).",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /href\s*=\s*\{?\s*(?:.*(?:user|input|data|url|link|query)|`[^`]*\$\{)(?![\s\S]{0,50}(?:startsWith|protocol|http))/gi,
    ],
  },
  {
    id: "xss-eval-user",
    title: "XSS: eval() with User-Controlled String",
    description:
      "eval() executes arbitrary JavaScript. User input reaching eval enables complete client-side compromise.",
    severity: "critical",
    cwe: "CWE-79",
    patterns: [/eval\s*\(\s*(?:.*(?:location|search|hash|input|user|data|query)|`[^`]*\$\{)/gi],
  },
  {
    id: "xss-template-unescaped",
    title: "XSS: Unescaped Output in Template",
    description:
      "Template renders unescaped HTML (<%- in EJS, |safe in Jinja2, {{{ in Handlebars, v-html in Vue).",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /<%-\s*(?:user|input|data|content|message|body)/gi,
      /\|\s*safe\b/gi,
      /\{\{\{\s*(?:user|input|data|content)/gi,
      /v-html\s*=\s*["'](?:user|input|data|content|message)/gi,
    ],
  },
  {
    id: "xss-json-inject",
    title: "XSS: JSON Embedded in HTML Without Encoding",
    description:
      "JSON data embedded in <script> tag without HTML entity encoding. A </script> in data breaks out.",
    severity: "medium",
    cwe: "CWE-79",
    patterns: [
      /<script>.*JSON\.stringify\s*\(.*(?:user|data|input|req)/gi,
      /window\.__DATA__\s*=\s*(?:<%|{{|<\?)/gi,
    ],
  },
  {
    id: "xss-postmessage",
    title: "XSS: postMessage Data Used in DOM Without Sanitization",
    description:
      "Data from postMessage event used in innerHTML or eval. Validate origin and sanitize data.",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /addEventListener\s*\(\s*['"]message['"][\s\S]{0,200}(?:innerHTML|eval|document\.write)/gi,
      /onmessage[\s\S]{0,200}(?:innerHTML|eval)/gi,
    ],
  },
];

export interface XssDeepScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class XssDeepScanner {
  async scan(projectPath: string): Promise<XssDeepScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.html", "**/*.ejs", "**/*.hbs"],
      {
        cwd: projectPath,
        absolute: true,
        ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
        nodir: true,
      }
    );
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
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of XSS_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({
                id: `XSS-${String(id++).padStart(4, "0")}`,
                rule: `xss:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "xss",
                cwe: rule.cwe,
                confidence: "high",
                location: { file: rel, line: i + 1, snippet: lines[i].trim() },
              });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
