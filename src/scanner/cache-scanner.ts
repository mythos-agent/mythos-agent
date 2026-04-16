import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const CACHE_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "cache-sensitive-data",
    title: "Cache: Sensitive Data in Cache",
    description: "Passwords, tokens, or PII stored in cache (Redis, Memcached). Cache data may be accessible without authentication.",
    severity: "high",
    cwe: "CWE-524",
    patterns: [
      /(?:redis|cache|memcached)\.\w*(?:set|put|store)\s*\(\s*['"].*(?:password|token|secret|ssn|creditCard)/gi,
    ],
  },
  {
    id: "cache-no-control-header",
    title: "Cache: Missing Cache-Control on Sensitive Endpoints",
    description: "API returning sensitive data without Cache-Control: no-store header. Responses may be cached by proxies/CDNs.",
    severity: "medium",
    cwe: "CWE-525",
    patterns: [
      /(?:\/api\/(?:user|account|profile|payment|admin))(?![\s\S]{0,300}(?:cache-control|no-store|no-cache|private))/gi,
    ],
  },
  {
    id: "cache-poisoning-host",
    title: "Cache: Host Header Used for Cache Key",
    description: "Application uses Host header in responses that are cached. Attackers can poison the cache with a malicious Host header.",
    severity: "high",
    cwe: "CWE-444",
    patterns: [
      /req\.(?:headers\.host|hostname|get\s*\(\s*['"]host['"])\s*.*(?:redirect|url|href|link|src)/gi,
    ],
  },
  {
    id: "cache-auth-data-shared",
    title: "Cache: Authenticated Data in Shared Cache",
    description: "Response with user-specific data may be cached and served to other users. Use Cache-Control: private or Vary: Cookie.",
    severity: "high",
    cwe: "CWE-524",
    patterns: [
      /res\.(?:setHeader|set)\s*\(\s*['"]Cache-Control['"].*(?:public|s-maxage|max-age)(?!.*private)/gi,
    ],
  },
  {
    id: "cache-no-vary",
    title: "Cache: Missing Vary Header on Auth Endpoint",
    description: "Cached response without Vary: Authorization/Cookie header. Different users may receive each other's cached responses.",
    severity: "medium",
    cwe: "CWE-524",
    patterns: [
      /(?:maxAge|max-age|s-maxage)(?![\s\S]{0,200}(?:Vary|vary))/gi,
    ],
  },
];

export interface CacheScanResult { findings: Vulnerability[]; filesScanned: number; }

export class CacheScanner {
  async scan(projectPath: string): Promise<CacheScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/cache|redis|memcache|Cache-Control|max-age|cdn|cloudfront|varnish/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of CACHE_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({ id: `CACHE-${String(id++).padStart(4, "0")}`, rule: `cache:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "cache", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" } });
            break;
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
