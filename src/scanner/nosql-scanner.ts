import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const NOSQL_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "nosql-operator-injection",
    title: "NoSQL: Operator Injection via Object Input",
    description: "MongoDB query built from user object input. Attacker can inject $gt, $ne, $regex operators to bypass auth or extract data.",
    severity: "critical",
    cwe: "CWE-943",
    patterns: [
      /\.find\s*\(\s*(?:req\.body|req\.query|JSON\.parse)/gi,
      /\.findOne\s*\(\s*(?:req\.body|req\.query)/gi,
      /\.deleteMany\s*\(\s*(?:req\.body|req\.query)/gi,
      /\.updateMany\s*\(\s*(?:req\.body|req\.query)/gi,
    ],
  },
  {
    id: "nosql-where-string",
    title: "NoSQL: $where with String Expression",
    description: "MongoDB $where clause with string enables JavaScript injection. Use standard query operators instead.",
    severity: "critical",
    cwe: "CWE-943",
    patterns: [
      /\$where\s*:\s*(?:['"`]|req\.|input|user|data)/gi,
      /\.find\s*\(\s*\{\s*\$where/gi,
    ],
  },
  {
    id: "nosql-regex-injection",
    title: "NoSQL: User Input in $regex Query",
    description: "User input in MongoDB $regex without escaping. Attackers can craft regex for ReDoS or data extraction.",
    severity: "high",
    cwe: "CWE-943",
    patterns: [
      /\$regex\s*:\s*(?:req\.|input|user|data|query|new\s+RegExp\s*\(\s*req)/gi,
    ],
  },
  {
    id: "nosql-mapreduce",
    title: "NoSQL: mapReduce with User Input",
    description: "MongoDB mapReduce executes JavaScript. User input in map/reduce functions enables code execution.",
    severity: "critical",
    cwe: "CWE-94",
    patterns: [
      /mapReduce\s*\([\s\S]{0,100}(?:req\.|input|user|data)/gi,
    ],
  },
  {
    id: "nosql-aggregate-lookup",
    title: "NoSQL: User Input in Aggregate Pipeline",
    description: "User input in MongoDB aggregate pipeline ($lookup, $group) can access unauthorized collections.",
    severity: "high",
    cwe: "CWE-943",
    patterns: [
      /aggregate\s*\(\s*\[[\s\S]{0,200}(?:req\.|input|user|body)/gi,
    ],
  },
];

export interface NosqlScanResult { findings: Vulnerability[]; filesScanned: number; }

export class NosqlScanner {
  async scan(projectPath: string): Promise<NosqlScanResult> {
    const files = await glob(["**/*.ts", "**/*.js"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/mongo|mongoose|collection|aggregate|findOne|find\(|mapReduce/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of NOSQL_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `NOSQL-${String(id++).padStart(4, "0")}`, rule: `nosql:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "nosql-injection", cwe: rule.cwe, confidence: "high", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
