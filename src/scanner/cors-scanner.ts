import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const CORS_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "cors-wildcard-origin",
    title: "CORS: Wildcard Origin (*)",
    description: "CORS allows any origin. Any website can make requests to your API, including reading responses.",
    severity: "high",
    cwe: "CWE-942",
    patterns: [
      /Access-Control-Allow-Origin\s*[:=]\s*['"]?\s*\*/gi,
      /origin\s*:\s*(?:true|['"]?\s*\*\s*['"]?)/gi,
    ],
  },
  {
    id: "cors-reflect-origin",
    title: "CORS: Origin Reflected Without Validation",
    description: "The Origin header is reflected as-is in Access-Control-Allow-Origin. This is equivalent to wildcard with credentials.",
    severity: "critical",
    cwe: "CWE-942",
    patterns: [
      /Access-Control-Allow-Origin.*req\.headers\.origin/gi,
      /Access-Control-Allow-Origin.*request\.headers\.get\s*\(\s*['"]origin['"]/gi,
      /origin\s*:\s*(?:req|request)\.(?:headers\.)?origin/gi,
    ],
  },
  {
    id: "cors-credentials-wildcard",
    title: "CORS: Credentials with Wildcard Origin",
    description: "CORS allows credentials (cookies) with wildcard origin. Browsers block this, but misconfigured proxies may not.",
    severity: "high",
    cwe: "CWE-942",
    patterns: [
      /credentials\s*:\s*true[\s\S]{0,100}origin\s*:\s*(?:true|\*)/gi,
      /Access-Control-Allow-Credentials.*true[\s\S]{0,100}Access-Control-Allow-Origin.*\*/gi,
    ],
  },
  {
    id: "cors-null-origin",
    title: "CORS: Null Origin Allowed",
    description: "CORS allows 'null' origin. Sandboxed iframes and file:// URLs send null origin, enabling exploitation.",
    severity: "medium",
    cwe: "CWE-942",
    patterns: [
      /(?:allowedOrigins|whitelist|origin).*['"]null['"]/gi,
      /Access-Control-Allow-Origin.*null/gi,
    ],
  },
  {
    id: "cors-substring-match",
    title: "CORS: Origin Validated with Substring Match",
    description: "Origin checked with includes() or indexOf() instead of exact match. evil-example.com passes a check for example.com.",
    severity: "high",
    cwe: "CWE-942",
    patterns: [
      /origin\.(?:includes|indexOf|endsWith)\s*\(/gi,
      /origin.*\.match\s*\(\s*(?!\/\^)/gi,
    ],
  },
  {
    id: "cors-preflight-cache-long",
    title: "CORS: Preflight Cache Too Long",
    description: "Access-Control-Max-Age set very high (>86400). Changes to CORS policy won't take effect for cached clients.",
    severity: "low",
    cwe: "CWE-693",
    patterns: [
      /Access-Control-Max-Age\s*[:=]\s*['"]?\d{6,}/gi,
      /maxAge\s*:\s*(?:\d{6,}|Infinity)/gi,
    ],
  },
  {
    id: "cors-expose-all-headers",
    title: "CORS: Exposing All Response Headers",
    description: "Access-Control-Expose-Headers set to * exposes all headers including potentially sensitive ones.",
    severity: "medium",
    cwe: "CWE-200",
    patterns: [
      /Access-Control-Expose-Headers\s*[:=]\s*['"]?\s*\*/gi,
      /exposedHeaders\s*:\s*\[\s*['"]?\*['"]?\s*\]/gi,
    ],
  },
];

export interface CorsScanResult { findings: Vulnerability[]; filesScanned: number; }

export class CorsScanner {
  async scan(projectPath: string): Promise<CorsScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/cors|origin|Access-Control/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of CORS_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `CORS-${String(id++).padStart(4, "0")}`, rule: `cors:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "cors", cwe: rule.cwe, confidence: "high", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
