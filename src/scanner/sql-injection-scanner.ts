import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const SQLI_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "sqli-template-literal",
    title: "SQL Injection: Template Literal in Query",
    description: "SQL query built with template literal containing user input. Use parameterized queries ($1, ?) instead.",
    severity: "critical",
    cwe: "CWE-89",
    patterns: [
      /(?:query|execute|exec|raw)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE).*\$\{/gi,
    ],
  },
  {
    id: "sqli-string-concat",
    title: "SQL Injection: String Concatenation in Query",
    description: "SQL query built with string concatenation. Attacker input can alter the query structure.",
    severity: "critical",
    cwe: "CWE-89",
    patterns: [
      /(?:query|execute)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*["']\s*\+/gi,
      /(?:query|execute)\s*\(\s*.*\+\s*["'].*(?:WHERE|AND|OR|SET|VALUES)/gi,
    ],
  },
  {
    id: "sqli-fstring-python",
    title: "SQL Injection: Python f-string in SQL Query",
    description: "SQL query built with Python f-string. Use parameterized queries with %s or ? placeholders.",
    severity: "critical",
    cwe: "CWE-89",
    patterns: [
      /(?:cursor\.execute|db\.execute|session\.execute)\s*\(\s*f["'](?:SELECT|INSERT|UPDATE|DELETE)/gi,
      /(?:cursor\.execute|db\.execute)\s*\(\s*["'].*["']\s*%\s*(?:\(|req|input|user)/gi,
    ],
  },
  {
    id: "sqli-orm-raw",
    title: "SQL Injection: Raw Query in ORM with User Input",
    description: "ORM raw/literal query with interpolated user input. Even with ORMs, raw queries need parameterization.",
    severity: "critical",
    cwe: "CWE-89",
    patterns: [
      /\.raw\s*\(\s*`.*\$\{/gi,
      /\.raw\s*\(\s*["'].*["']\s*\+/gi,
      /sequelize\.query\s*\(\s*`.*\$\{/gi,
      /Sequelize\.literal\s*\(\s*`.*\$\{/gi,
      /knex\.raw\s*\(\s*`.*\$\{/gi,
    ],
  },
  {
    id: "sqli-like-injection",
    title: "SQL Injection: Unescaped LIKE Clause",
    description: "User input in SQL LIKE clause without escaping % and _ wildcards. Enables data extraction via wildcard injection.",
    severity: "medium",
    cwe: "CWE-89",
    patterns: [
      /LIKE\s*['"]%.*\$\{/gi,
      /LIKE\s*['"]%.*\+\s*(?:req|input|user|query|search)/gi,
    ],
  },
  {
    id: "sqli-order-by",
    title: "SQL Injection: User Input in ORDER BY",
    description: "User input in ORDER BY clause. ORDER BY doesn't accept parameterized values — use a whitelist of allowed columns.",
    severity: "high",
    cwe: "CWE-89",
    patterns: [
      /ORDER\s+BY\s*.*(?:\$\{|.*\+\s*)(?:req|input|user|sort|order|column)/gi,
    ],
  },
];

export interface SqlInjectionScanResult { findings: Vulnerability[]; filesScanned: number; }

export class SqlInjectionScanner {
  async scan(projectPath: string): Promise<SqlInjectionScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.php"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/query|execute|SELECT|INSERT|UPDATE|DELETE|sequelize|knex|prisma|cursor/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of SQLI_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `SQLI-${String(id++).padStart(4, "0")}`, rule: `sqli:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "sql-injection", cwe: rule.cwe, confidence: "high", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
