import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const UPLOAD_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "upload-no-type-check",
    title: "Upload: No File Type Validation",
    description:
      "File upload without MIME type or extension validation. Attackers can upload executable files, web shells, or malware.",
    severity: "high",
    cwe: "CWE-434",
    patterns: [
      /multer\s*\(\s*\{(?![\s\S]{0,300}(?:fileFilter|mimetype|extension))/gi,
      /upload\.(?:single|array|fields)\s*\((?![\s\S]{0,200}(?:filter|validate|check|mime))/gi,
      /formidable\s*\(\s*\{(?![\s\S]{0,200}(?:filter|allowedTypes|mimetype))/gi,
    ],
  },
  {
    id: "upload-no-size-limit",
    title: "Upload: No File Size Limit",
    description:
      "File upload without size restriction. Attackers can upload huge files to exhaust disk space or memory.",
    severity: "medium",
    cwe: "CWE-770",
    patterns: [
      /multer\s*\(\s*\{(?![\s\S]{0,300}(?:limits|fileSize|maxFileSize))/gi,
      /bodyParser\.raw\s*\(\s*\{(?![\s\S]{0,100}limit)/gi,
    ],
  },
  {
    id: "upload-path-traversal",
    title: "Upload: Filename Used Without Sanitization",
    description:
      "Original filename from upload used in file path. Attacker can use ../../../etc/cron.d/backdoor as filename.",
    severity: "critical",
    cwe: "CWE-22",
    patterns: [
      /(?:originalname|filename|file\.name).*(?:path\.join|writeFile|createWriteStream)/gi,
      /req\.files?\.\w+\.(?:name|originalname).*(?:fs\.|path\.)/gi,
    ],
  },
  {
    id: "upload-executable",
    title: "Upload: No Executable File Blocking",
    description:
      "Upload does not block executable file types (.exe, .sh, .php, .jsp, .py). These can be executed on the server.",
    severity: "high",
    cwe: "CWE-434",
    patterns: [
      /(?:upload|multer|formidable)(?![\s\S]{0,500}(?:\.exe|\.sh|\.php|\.jsp|\.py|\.bat|\.cmd|executable|blacklist|denylist))/gi,
    ],
  },
  {
    id: "upload-public-dir",
    title: "Upload: Files Stored in Public Directory",
    description:
      "Uploaded files stored in publicly accessible directory. Uploaded scripts could be executed by the web server.",
    severity: "high",
    cwe: "CWE-434",
    patterns: [
      /(?:destination|dest|uploadDir|upload_to)\s*[:=]\s*['"](?:\.\/)?(?:public|static|www|htdocs|uploads)/gi,
    ],
  },
];

export interface UploadScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class UploadScanner {
  async scan(projectPath: string): Promise<UploadScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
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
      if (!/upload|multer|formidable|busboy|multipart|file/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of UPLOAD_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `UPLOAD-${String(id++).padStart(4, "0")}`,
              rule: `upload:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "upload",
              cwe: rule.cwe,
              confidence: "medium",
              location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" },
            });
            break;
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
