import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const INPUT_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "input-no-schema",
    title: "Input: No Schema Validation on Request Body",
    description: "Request body used without schema validation (joi, zod, yup, ajv). Malformed input can cause crashes or security issues.",
    severity: "medium",
    cwe: "CWE-20",
    patterns: [
      /req\.body\.\w+(?![\s\S]{0,200}(?:validate|schema|parse|safeParse|joi|zod|yup|ajv|check|assert))/gi,
    ],
  },
  {
    id: "input-no-type-check",
    title: "Input: No Type Checking on User Input",
    description: "User input used without verifying its type. typeof checks prevent type confusion attacks.",
    severity: "medium",
    cwe: "CWE-20",
    patterns: [
      /(?:parseInt|Number)\s*\(\s*req\.(?:query|params)\.\w+\s*\)(?![\s\S]{0,50}(?:isNaN|Number\.isFinite|isInteger))/gi,
    ],
  },
  {
    id: "input-no-length-limit",
    title: "Input: No Length Limit on String Input",
    description: "String input accepted without length validation. Attackers can send extremely long strings to exhaust memory.",
    severity: "medium",
    cwe: "CWE-770",
    patterns: [
      /req\.body\.(?:name|title|description|content|message|comment|bio|text)\b(?![\s\S]{0,100}(?:length|maxLength|max|limit|slice|substring|truncate))/gi,
    ],
  },
  {
    id: "input-no-email-validation",
    title: "Input: Email Used Without Validation",
    description: "Email field used without format validation. Invalid emails can cause errors or be used for injection.",
    severity: "low",
    cwe: "CWE-20",
    patterns: [
      /req\.body\.email(?![\s\S]{0,100}(?:validate|isEmail|match|regex|test|includes\s*\(\s*['"]@))/gi,
    ],
  },
  {
    id: "input-direct-db-query",
    title: "Input: User Input Directly in Database Query",
    description: "Request parameter used directly in database query without sanitization or parameterization.",
    severity: "high",
    cwe: "CWE-89",
    patterns: [
      /\.(?:where|find|filter)\s*\(\s*\{\s*\w+\s*:\s*req\.(?:query|params|body)\.\w+\s*\}/gi,
    ],
  },
  {
    id: "input-no-sanitize-html",
    title: "Input: HTML Input Without Sanitization",
    description: "User-provided HTML content used without sanitization. Use DOMPurify or similar to prevent XSS.",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /(?:content|html|body|message|comment)\s*[:=]\s*req\.body\.(?:content|html|body|message)(?![\s\S]{0,100}(?:sanitize|purify|escape|strip|bleach))/gi,
    ],
  },
  {
    id: "input-url-no-validate",
    title: "Input: URL Input Without Validation",
    description: "User-provided URL used without protocol/domain validation. Can enable SSRF or redirect to malicious sites.",
    severity: "high",
    cwe: "CWE-20",
    patterns: [
      /(?:url|link|href|redirect|callback|webhook)\s*[:=]\s*req\.(?:body|query)\.\w+(?![\s\S]{0,100}(?:URL|validate|parse|startsWith|protocol|hostname|whitelist|allowlist))/gi,
    ],
  },
  {
    id: "input-array-no-limit",
    title: "Input: Array Input Without Size Limit",
    description: "Array from request body processed without size limit. Attackers can send huge arrays to cause DoS.",
    severity: "medium",
    cwe: "CWE-770",
    patterns: [
      /req\.body\.\w+\.(?:map|forEach|filter|reduce|every|some)\s*\((?![\s\S]{0,100}(?:slice|length\s*[<>]|limit|max))/gi,
    ],
  },
];

export interface InputValidationScanResult { findings: Vulnerability[]; filesScanned: number; }

export class InputValidationScanner {
  async scan(projectPath: string): Promise<InputValidationScanResult> {
    const files = await glob(["**/*.ts", "**/*.js"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/req\.|request\./i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of INPUT_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `INPUT-${String(id++).padStart(4, "0")}`, rule: `input:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "input-validation", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
