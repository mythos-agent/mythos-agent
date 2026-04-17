import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const SESSION_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "session-no-expiry",
    title: "Session: No Session Expiry",
    description:
      "Session configured without expiration/maxAge. Sessions persist indefinitely, increasing hijacking window.",
    severity: "high",
    cwe: "CWE-613",
    patterns: [/session\s*\(\s*\{(?![\s\S]{0,300}(?:maxAge|expires|ttl|cookie.*maxAge))/gi],
  },
  {
    id: "session-fixation",
    title: "Session: No Session Regeneration After Login",
    description:
      "Session ID not regenerated after authentication. Enables session fixation attacks.",
    severity: "high",
    cwe: "CWE-384",
    patterns: [
      /(?:login|authenticate|signIn)[\s\S]{0,500}(?:req\.session\.\w+\s*=)(?![\s\S]{0,200}(?:regenerate|destroy|create))/gi,
    ],
  },
  {
    id: "session-insecure-cookie",
    title: "Session: Cookie Missing Security Flags",
    description:
      "Session cookie without httpOnly, secure, or sameSite flags. Vulnerable to XSS theft and CSRF.",
    severity: "high",
    cwe: "CWE-614",
    patterns: [
      /cookie\s*:\s*\{(?![\s\S]{0,200}httpOnly\s*:\s*true)/gi,
      /cookie\s*:\s*\{(?![\s\S]{0,200}secure\s*:\s*true)/gi,
    ],
  },
  {
    id: "session-predictable-id",
    title: "Session: Predictable Session ID Generation",
    description:
      "Session ID generated using Math.random() or sequential numbers. Use crypto.randomBytes() or a session library.",
    severity: "critical",
    cwe: "CWE-330",
    patterns: [
      /(?:sessionId|session_id|sid)\s*[:=]\s*(?:Math\.random|Date\.now|uuid\.v1|counter|increment)/gi,
    ],
  },
  {
    id: "session-no-logout-invalidation",
    title: "Session: No Session Invalidation on Logout",
    description:
      "Logout handler does not destroy or invalidate the session. Old session tokens remain valid.",
    severity: "medium",
    cwe: "CWE-613",
    patterns: [
      /(?:logout|signOut|sign_out)[\s\S]{0,300}(?:res\.(?:redirect|json|send))(?![\s\S]{0,200}(?:destroy|invalidate|delete|clear|remove))/gi,
    ],
  },
  {
    id: "session-stored-client",
    title: "Session: Sensitive Data in Client-Side Storage",
    description:
      "Sensitive data stored in localStorage/sessionStorage. These are accessible to XSS attacks. Use httpOnly cookies.",
    severity: "high",
    cwe: "CWE-922",
    patterns: [
      /localStorage\.setItem\s*\(\s*['"](?:token|jwt|session|auth|user|password|secret)/gi,
      /sessionStorage\.setItem\s*\(\s*['"](?:token|jwt|auth|secret)/gi,
    ],
  },
  {
    id: "session-no-rotation-on-privilege",
    title: "Session: No Session Rotation on Privilege Change",
    description:
      "Session not regenerated when user role or permissions change. Old session retains previous privilege level.",
    severity: "medium",
    cwe: "CWE-384",
    patterns: [
      /(?:role|permission|admin|privilege)\s*[:=](?![\s\S]{0,200}(?:regenerate|newSession|destroy))/gi,
    ],
  },
];

export interface SessionScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class SessionScanner {
  async scan(projectPath: string): Promise<SessionScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"], {
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
      if (!/session|cookie|localStorage|sessionStorage|jwt|token|auth/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of SESSION_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `SESS-${String(id++).padStart(4, "0")}`,
              rule: `session:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "session",
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
