import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const EMAIL_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "email-header-injection",
    title: "Email: Header Injection",
    description: "User input in email headers (To, Subject, CC, BCC). Attackers can inject additional headers to send spam or phish.",
    severity: "high",
    cwe: "CWE-93",
    patterns: [
      /(?:to|from|subject|cc|bcc)\s*[:=]\s*(?:req\.|input|user|data|body)/gi,
      /sendMail\s*\(\s*\{[\s\S]{0,100}(?:to|subject|from)\s*:\s*(?:req\.|input|user)/gi,
    ],
  },
  {
    id: "email-html-no-sanitize",
    title: "Email: HTML Email with User Content",
    description: "User content included in HTML email without sanitization. Enables phishing via styled HTML or script injection in email clients.",
    severity: "medium",
    cwe: "CWE-79",
    patterns: [
      /html\s*:\s*(?:`[^`]*\$\{(?:user|input|data|req)|.*\+\s*(?:user|input|data|req))/gi,
    ],
  },
  {
    id: "email-smtp-credentials",
    title: "Email: SMTP Credentials Hardcoded",
    description: "SMTP username/password hardcoded in source. Use environment variables for email service credentials.",
    severity: "high",
    cwe: "CWE-798",
    patterns: [
      /(?:smtp|mail|email).*(?:user|pass|password|auth)\s*[:=]\s*['"][^'"]{4,}['"]/gi,
      /createTransport\s*\(\s*\{[\s\S]{0,200}(?:user|pass)\s*:\s*['"][^'"]+['"]/gi,
    ],
  },
  {
    id: "email-enumeration",
    title: "Email: User Enumeration via Error Messages",
    description: "Different error messages for 'email not found' vs 'wrong password' enable username enumeration.",
    severity: "medium",
    cwe: "CWE-204",
    patterns: [
      /(?:email|user).*(?:not found|does not exist|invalid email)(?![\s\S]{0,100}(?:same|generic|consistent))/gi,
    ],
  },
];

export interface EmailScanResult { findings: Vulnerability[]; filesScanned: number; }

export class EmailScanner {
  async scan(projectPath: string): Promise<EmailScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/email|smtp|sendMail|transporter|nodemailer|sendgrid|mailgun/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of EMAIL_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({ id: `EMAIL-${String(id++).padStart(4, "0")}`, rule: `email:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "email", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" } });
            break;
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
