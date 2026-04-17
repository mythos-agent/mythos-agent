import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const PERM_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "perm-world-writable",
    title: "Permissions: World-Writable File Created",
    description:
      "File created with 0o777 or 0o666 permissions. Any user on the system can read/modify it.",
    severity: "high",
    cwe: "CWE-732",
    patterns: [
      /(?:chmod|writeFile|mkdirSync|createWriteStream).*(?:0o?777|0o?666|0777|0666)/gi,
      /os\.chmod\s*\(.*0o?777/gi,
    ],
  },
  {
    id: "perm-temp-file-insecure",
    title: "Permissions: Insecure Temporary File",
    description:
      "Temporary file created in predictable location without secure permissions. Use os.tmpdir() + crypto.randomUUID().",
    severity: "medium",
    cwe: "CWE-377",
    patterns: [
      /(?:writeFile|createWriteStream)\s*\(\s*['"]\/tmp\/[^'"]*['"]/gi,
      /open\s*\(\s*['"]\/tmp\//gi,
      /tempfile\.mktemp\s*\(/gi,
    ],
  },
  {
    id: "perm-umask-zero",
    title: "Permissions: umask Set to 0",
    description:
      "Process umask set to 0 means all new files are world-readable/writable. Set restrictive umask (0o077).",
    severity: "high",
    cwe: "CWE-732",
    patterns: [/process\.umask\s*\(\s*0\s*\)/gi, /os\.umask\s*\(\s*0o?0+\s*\)/gi],
  },
  {
    id: "perm-private-key-readable",
    title: "Permissions: Private Key File Without Restricted Permissions",
    description:
      "Private key file created without 0o600 permissions. Private keys must only be readable by the owner.",
    severity: "high",
    cwe: "CWE-732",
    patterns: [
      /(?:writeFile|createWriteStream).*(?:private.*key|\.pem|\.key)(?![\s\S]{0,100}(?:0o?600|0600|mode))/gi,
    ],
  },
  {
    id: "perm-directory-listing",
    title: "Permissions: Static File Directory Listing Enabled",
    description:
      "Express static middleware may expose directory listings. Disable with dotfiles:'deny' and index:false.",
    severity: "medium",
    cwe: "CWE-548",
    patterns: [/express\.static\s*\((?![\s\S]{0,100}(?:dotfiles|index\s*:\s*false))/gi],
  },
];

export interface PermissionScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class PermissionScanner {
  async scan(projectPath: string): Promise<PermissionScanResult> {
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
      if (!/chmod|umask|permission|0o?7|tmp|static|writeFile|createWriteStream/i.test(content))
        continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of PERM_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({
                id: `PERM-${String(id++).padStart(4, "0")}`,
                rule: `perm:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "permissions",
                cwe: rule.cwe,
                confidence: "medium",
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
