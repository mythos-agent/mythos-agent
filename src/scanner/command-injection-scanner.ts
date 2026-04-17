import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const CMD_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "cmdi-exec-template",
    title: "Command Injection: Template Literal in exec()",
    description:
      "User input interpolated into shell command via template literal. Use execFile() with argument array instead.",
    severity: "critical",
    cwe: "CWE-78",
    patterns: [/(?:exec|execSync)\s*\(\s*`[^`]*\$\{.*(?:req|input|user|data|params|query|body)/gi],
  },
  {
    id: "cmdi-exec-concat",
    title: "Command Injection: String Concatenation in exec()",
    description:
      "User input concatenated into shell command string. Use spawnSync with argument array.",
    severity: "critical",
    cwe: "CWE-78",
    patterns: [
      /(?:exec|execSync)\s*\(\s*(?:['"][^'"]*['"]\s*\+|.*\+\s*['"][^'"]*['"]).*(?:req|input|user|data|params)/gi,
    ],
  },
  {
    id: "cmdi-spawn-shell",
    title: "Command Injection: spawn() with shell:true",
    description:
      "spawn() with shell:true interprets shell metacharacters. Remove shell option and pass arguments as array.",
    severity: "high",
    cwe: "CWE-78",
    patterns: [/spawn\s*\(.*\{[\s\S]{0,100}shell\s*:\s*true/gi],
  },
  {
    id: "cmdi-python-os-system",
    title: "Command Injection: os.system() with User Input",
    description:
      "Python os.system() passes string to shell. Use subprocess.run() with argument list and shell=False.",
    severity: "critical",
    cwe: "CWE-78",
    patterns: [
      /os\.system\s*\(\s*(?:f['"]|.*\+|.*format|.*%.*(?:request|input|user))/gi,
      /os\.popen\s*\(\s*(?:f['"]|.*\+|.*format)/gi,
    ],
  },
  {
    id: "cmdi-subprocess-shell",
    title: "Command Injection: subprocess with shell=True",
    description:
      "Python subprocess with shell=True passes string to shell. Use shell=False with argument list.",
    severity: "high",
    cwe: "CWE-78",
    patterns: [/subprocess\.(?:run|call|Popen|check_output)\s*\(.*shell\s*=\s*True/gi],
  },
  {
    id: "cmdi-go-exec-command",
    title: "Command Injection: Go exec.Command with Shell",
    description:
      "Go exec.Command with 'sh -c' and user input enables command injection. Pass arguments separately.",
    severity: "critical",
    cwe: "CWE-78",
    patterns: [
      /exec\.Command\s*\(\s*["'](?:sh|bash|cmd)["']\s*,\s*["']-c["'].*(?:r\.|req\.|input|user)/gi,
    ],
  },
];

export interface CommandInjectionScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class CommandInjectionScanner {
  async scan(projectPath: string): Promise<CommandInjectionScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py", "**/*.go"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
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
      if (!/exec|spawn|system|popen|subprocess|child_process|Command/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of CMD_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({
                id: `CMDI-${String(id++).padStart(4, "0")}`,
                rule: `cmdi:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "command-injection",
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
