import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

export interface JwtRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
  /**
   * Optional post-match mitigation check. Called after a pattern fires.
   * Receives the file's lines array and the 1-based line number of the match.
   * Return true when a mitigation is detected — suppresses the finding.
   * Use this instead of negative lookaheads to avoid ReDoS.
   */
  mitigationCheck?: (lines: string[], lineNum: number) => boolean;
}

const JWT_RULES: JwtRule[] = [
  {
    id: "jwt-none-algorithm",
    title: "JWT: None Algorithm Accepted",
    description:
      "JWT verification accepts 'none' algorithm. Attackers can forge tokens without a secret.",
    severity: "critical",
    cwe: "CWE-345",
    patterns: [/algorithms\s*:\s*\[.*['"]none['"]/gi, /algorithm\s*[:=]\s*['"]none['"]/gi],
  },
  {
    id: "jwt-decode-without-verify",
    title: "JWT: Decode Without Verification",
    description:
      "jwt.decode() does not verify the signature. Always use jwt.verify() to validate tokens.",
    severity: "critical",
    cwe: "CWE-345",
    patterns: [/jwt\.decode\s*\(/gi, /jose\.decodeJwt\s*\(/gi],
  },
  {
    id: "jwt-weak-secret",
    title: "JWT: Weak/Short Signing Secret",
    description:
      "JWT signed with a short or common string. Use at least 256-bit random secret or RSA/EC keys.",
    severity: "critical",
    cwe: "CWE-326",
    patterns: [
      /jwt\.sign\s*\([^)]*,\s*['"][^'"]{1,15}['"]/gi,
      /(?:JWT_SECRET|TOKEN_SECRET|SECRET_KEY)\s*[:=]\s*['"][^'"]{1,15}['"]/gi,
    ],
  },
  {
    id: "jwt-no-expiry",
    title: "JWT: Token Without Expiration",
    description: "JWT signed without expiresIn/exp claim. Tokens are valid forever if not expired.",
    severity: "high",
    cwe: "CWE-613",
    patterns: [/jwt\.sign\s*\(\s*\{/gi],
    // ~200 chars ≈ 10 lines; check that window for expiry options.
    mitigationCheck(lines: string[], lineNum: number): boolean {
      const windowStr = lines.slice(Math.max(0, lineNum - 1), lineNum - 1 + 10).join("\n");
      return windowStr.includes("expiresIn") || /exp\s*:/.test(windowStr);
    },
  },
  {
    id: "jwt-stored-localstorage",
    title: "JWT: Token Stored in localStorage",
    description:
      "JWT stored in localStorage is accessible to XSS attacks. Use httpOnly cookies instead.",
    severity: "high",
    cwe: "CWE-922",
    patterns: [
      /localStorage\.setItem\s*\(\s*['"](?:token|jwt|access_token|auth_token)/gi,
      /localStorage\[['"]token['"]\]\s*=/gi,
    ],
  },
  {
    id: "jwt-no-audience",
    title: "JWT: No Audience Validation",
    description:
      "JWT verified without audience (aud) check. Tokens from other services may be accepted.",
    severity: "medium",
    cwe: "CWE-287",
    patterns: [/jwt\.verify\s*\([^)]*(?!.*audience)(?!.*aud)/gi],
  },
  {
    id: "jwt-no-issuer",
    title: "JWT: No Issuer Validation",
    description:
      "JWT verified without issuer (iss) check. Tokens from untrusted issuers may be accepted.",
    severity: "medium",
    cwe: "CWE-287",
    patterns: [/jwt\.verify\s*\([^)]*(?!.*issuer)(?!.*iss)/gi],
  },
  {
    id: "jwt-secret-in-code",
    title: "JWT: Signing Secret Hardcoded",
    description:
      "JWT signing secret is hardcoded in source code. Use environment variables or a secrets manager.",
    severity: "high",
    cwe: "CWE-798",
    patterns: [/jwt\.sign\s*\([^)]*,\s*['"][A-Za-z0-9+/=]{20,}['"]/gi],
  },
  {
    id: "jwt-no-revocation",
    title: "JWT: No Token Revocation Mechanism",
    description:
      "JWT-based auth without token blacklist or revocation. Compromised tokens remain valid until expiry.",
    severity: "medium",
    cwe: "CWE-613",
    patterns: [/jwt\.verify/gi],
    // ~500 chars ≈ 20 lines; check that window for a revocation mechanism.
    mitigationCheck(lines: string[], lineNum: number): boolean {
      const window = lines.slice(Math.max(0, lineNum - 1), lineNum - 1 + 20).join("\n");
      return (
        window.includes("blacklist") ||
        window.includes("revoke") ||
        window.includes("invalidate") ||
        window.includes("redis") ||
        window.includes("cache") ||
        window.includes("blocklist")
      );
    },
  },
];

/**
 * Return the first unmitigated match across all patterns of `rule`, or null
 * if every match is either absent or suppressed by `mitigationCheck`.
 *
 * Decouples per-pattern matching from per-pattern mitigation checking, so a
 * multi-pattern rule with a `mitigationCheck` that fires on one pattern can
 * still surface a finding from a later pattern at an unmitigated site.
 */
export function findUnmitigatedMatch(
  rule: JwtRule,
  content: string,
  lines: string[]
): { line: number; index: number } | null {
  for (const p of rule.patterns) {
    p.lastIndex = 0;
    const match = p.exec(content);
    if (!match) continue;
    const ln = content.slice(0, match.index).split("\n").length;
    if (rule.mitigationCheck?.(lines, ln)) continue;
    return { line: ln, index: match.index };
  }
  return null;
}

export interface JwtScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class JwtScanner {
  async scan(projectPath: string): Promise<JwtScanResult> {
    const files = await glob(["**/*.ts", "**/*.js"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", ".mythos/**", "**/*.test.*"],
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
      if (!/jwt|jsonwebtoken|jose|token|bearer/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of JWT_RULES) {
        const m = findUnmitigatedMatch(rule, content, lines);
        if (!m) continue;
        findings.push({
          id: `JWT-${String(id++).padStart(4, "0")}`,
          rule: `jwt:${rule.id}`,
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          category: "jwt",
          cwe: rule.cwe,
          confidence: "medium",
          location: { file: rel, line: m.line, snippet: lines[m.line - 1]?.trim() || "" },
        });
      }
    }
    return { findings, filesScanned: files.length };
  }
}
