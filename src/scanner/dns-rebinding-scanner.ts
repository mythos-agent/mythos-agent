import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const DNS_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "dns-localhost-only-no-host-check",
    title: "DNS Rebinding: Localhost Service Without Host Validation",
    description:
      "Service binds to localhost/127.0.0.1 but does not validate the Host header. DNS rebinding can bypass same-origin policy to access it.",
    severity: "high",
    cwe: "CWE-350",
    patterns: [
      /\.listen\s*\(\s*\d+\s*,\s*['"](?:localhost|127\.0\.0\.1)['"](?![\s\S]{0,500}(?:host|hostname|whitelist|allowedHosts))/gi,
    ],
  },
  {
    id: "dns-cors-localhost",
    title: "DNS Rebinding: CORS Allows Localhost Origins",
    description:
      "CORS configured to allow localhost origins. Combined with DNS rebinding, any website can access this API.",
    severity: "medium",
    cwe: "CWE-942",
    patterns: [
      /Access-Control-Allow-Origin.*(?:localhost|127\.0\.0\.1)/gi,
      /origin\s*[:=].*(?:localhost|127\.0\.0\.1)/gi,
    ],
  },
  {
    id: "dns-internal-api-no-auth",
    title: "DNS Rebinding: Internal API Without Authentication",
    description:
      "API bound to localhost without authentication. If DNS rebinding is possible, external sites can access it.",
    severity: "high",
    cwe: "CWE-306",
    patterns: [
      /\.listen\s*\(\s*\d+\s*,\s*['"](?:localhost|127\.0\.0\.1|0\.0\.0\.0)['"][\s\S]{0,300}(?:\/api|\/admin|\/internal)(?![\s\S]{0,200}(?:auth|token|apiKey))/gi,
    ],
  },
  {
    id: "dns-dev-server-exposed",
    title: "DNS Rebinding: Dev Server Bound to 0.0.0.0",
    description:
      "Development server bound to all interfaces (0.0.0.0). This exposes it to the network, not just localhost.",
    severity: "medium",
    cwe: "CWE-668",
    patterns: [
      /\.listen\s*\(\s*\d+\s*,\s*['"]0\.0\.0\.0['"]/gi,
      /host\s*[:=]\s*['"]0\.0\.0\.0['"]/gi,
    ],
  },
];

export interface DnsRebindingScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class DnsRebindingScanner {
  async scan(projectPath: string): Promise<DnsRebindingScanResult> {
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
      if (!/listen|server|host|localhost|0\.0\.0\.0|127\.0\.0\.1/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of DNS_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `DNS-${String(id++).padStart(4, "0")}`,
              rule: `dns:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "dns-rebinding",
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
