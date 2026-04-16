import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const PATH_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "path-traversal-join",
    title: "Path: Traversal via path.join with User Input",
    description: "path.join does NOT prevent traversal. '../../../etc/passwd' passes through. Use path.resolve + startsWith check.",
    severity: "high",
    cwe: "CWE-22",
    patterns: [
      /path\.join\s*\(.*(?:req\.|params\.|query\.|body\.|input|user)/gi,
    ],
  },
  {
    id: "path-traversal-resolve",
    title: "Path: User Input in path.resolve Without Boundary Check",
    description: "path.resolve with user input but no check that result stays within the intended directory.",
    severity: "high",
    cwe: "CWE-22",
    patterns: [
      /path\.resolve\s*\(.*(?:req\.|params\.|query\.|body\.|input)(?![\s\S]{0,100}startsWith)/gi,
    ],
  },
  {
    id: "path-dot-dot",
    title: "Path: No .. Sanitization in File Path",
    description: "User input used in file path without stripping '..' sequences. Always validate the resolved path stays within bounds.",
    severity: "high",
    cwe: "CWE-22",
    patterns: [
      /(?:readFile|writeFile|createReadStream|createWriteStream|unlink|rmdir)\s*\(.*(?:req\.|input|user|data|params)(?![\s\S]{0,100}(?:startsWith|includes\s*\(\s*['"]\.\.['"]|sanitize|normalize))/gi,
    ],
  },
  {
    id: "path-null-byte",
    title: "Path: Potential Null Byte Injection",
    description: "File path from user input without null byte filtering. In older systems, null bytes can truncate paths to bypass extensions.",
    severity: "medium",
    cwe: "CWE-626",
    patterns: [
      /(?:readFile|open|access)\s*\(.*(?:req\.|input|user)(?![\s\S]{0,100}(?:replace.*\\0|replace.*%00|sanitize))/gi,
    ],
  },
  {
    id: "path-symlink",
    title: "Path: Symlink Following Without Check",
    description: "File operations follow symbolic links by default. Attackers can create symlinks to escape the intended directory.",
    severity: "medium",
    cwe: "CWE-59",
    patterns: [
      /(?:readFile|writeFile|stat|access)\s*\(.*(?:upload|user|public|tmp)(?![\s\S]{0,100}(?:lstat|realpath|readlink))/gi,
    ],
  },
];

export interface PathScanResult { findings: Vulnerability[]; filesScanned: number; }

export class PathScanner {
  async scan(projectPath: string): Promise<PathScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/path\.|readFile|writeFile|createReadStream|open|unlink|fs\./i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of PATH_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `PATH-${String(id++).padStart(4, "0")}`, rule: `path:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "path-traversal", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
