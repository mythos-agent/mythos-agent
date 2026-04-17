import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface ZeroTrustRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  filePatterns: string[];
  patterns: RegExp[];
}

const ZT_RULES: ZeroTrustRule[] = [
  // Implicit trust between services
  {
    id: "zt-implicit-trust",
    title: "Zero Trust: Implicit Trust Between Services",
    description:
      "Service-to-service communication without authentication. All requests should be verified regardless of network origin.",
    severity: "high",
    cwe: "CWE-287",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go"],
    patterns: [
      /fetch\s*\(\s*["']http:\/\/(?:localhost|127\.0\.0\.1|internal|service|backend)/gi,
      /axios\.\w+\s*\(\s*["']http:\/\/(?:localhost|internal|service)/gi,
      /requests\.(?:get|post)\s*\(\s*["']http:\/\/(?:localhost|internal)/gi,
    ],
  },

  // Missing mTLS
  {
    id: "zt-no-mtls",
    title: "Zero Trust: No Mutual TLS Between Services",
    description:
      "Service communication over plain HTTP or TLS without client certificate verification. Use mTLS for service-to-service auth.",
    severity: "medium",
    cwe: "CWE-295",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.yml", "**/*.yaml"],
    patterns: [
      /http:\/\/.*(?:service|api|backend|internal|microservice)/gi,
      /InsecureSkipVerify\s*:\s*true/gi,
      /rejectUnauthorized\s*:\s*false/gi,
      /verify\s*[:=]\s*False/gi,
    ],
  },

  // Overprivileged service accounts
  {
    id: "zt-overprivileged-service",
    title: "Zero Trust: Overprivileged Service Account",
    description:
      "Service running with admin/root privileges or wildcard permissions. Apply least-privilege principle.",
    severity: "high",
    cwe: "CWE-250",
    filePatterns: ["**/*.yml", "**/*.yaml", "**/*.tf", "**/*.json"],
    patterns: [
      /runAsUser\s*:\s*0/gi,
      /privileged\s*:\s*true/gi,
      /serviceAccountName\s*:\s*["']?(?:admin|root|default)/gi,
      /ClusterRoleBinding.*cluster-admin/gi,
    ],
  },

  // No network segmentation
  {
    id: "zt-no-network-policy",
    title: "Zero Trust: No Network Policy",
    description:
      "Kubernetes deployment without NetworkPolicy. All pods can communicate freely, violating zero-trust principles.",
    severity: "medium",
    cwe: "CWE-284",
    filePatterns: ["**/*.yml", "**/*.yaml"],
    patterns: [/kind:\s*Deployment(?![\s\S]{0,2000}NetworkPolicy)/gi],
  },

  // Trust based on IP/network
  {
    id: "zt-ip-trust",
    title: "Zero Trust: IP-Based Trust Decision",
    description:
      "Security decision based on IP address or network origin. IPs can be spoofed. Use identity-based verification.",
    severity: "medium",
    cwe: "CWE-290",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go"],
    patterns: [
      /(?:req\.ip|remoteAddress|x-forwarded-for).*(?:trusted|allowed|whitelist|isInternal)/gi,
      /(?:trusted|internal|safe).*(?:req\.ip|remoteAddr|REMOTE_ADDR)/gi,
    ],
  },

  // Missing service identity
  {
    id: "zt-no-service-auth",
    title: "Zero Trust: Internal API Without Service Authentication",
    description:
      "Internal API endpoint without service-to-service authentication (API key, JWT, mTLS). Every request must be authenticated.",
    severity: "high",
    cwe: "CWE-306",
    filePatterns: ["**/*.ts", "**/*.js"],
    patterns: [
      /(?:app|router)\.(?:get|post|put|delete)\s*\(\s*['"]\/internal\/(?!.*(?:auth|verify|token|apiKey|middleware))/gi,
      /(?:app|router)\.(?:get|post|put|delete)\s*\(\s*['"]\/api\/v\d+\/(?:health|status|metrics)['"](?!.*(?:auth|token))/gi,
    ],
  },

  // Shared secrets between services
  {
    id: "zt-shared-secret",
    title: "Zero Trust: Shared Secret Between Services",
    description:
      "Multiple services using the same secret/key. Compromise of one service compromises all. Use per-service credentials.",
    severity: "medium",
    cwe: "CWE-798",
    filePatterns: ["**/*.yml", "**/*.yaml", "**/*.env*"],
    patterns: [/SHARED_SECRET|COMMON_KEY|SERVICE_SECRET\s*[:=]/gi],
  },

  // No request signing
  {
    id: "zt-no-request-signing",
    title: "Zero Trust: Webhook/Callback Without Signature Verification",
    description:
      "Incoming webhook or callback processed without verifying the sender's signature. Always verify webhook signatures.",
    severity: "high",
    cwe: "CWE-345",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py"],
    patterns: [
      /(?:webhook|callback|hook)\s*(?:handler|endpoint|route)(?![\s\S]{0,300}(?:verify|signature|hmac|sign))/gi,
    ],
  },
];

export interface ZeroTrustScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class ZeroTrustScanner {
  async scan(projectPath: string): Promise<ZeroTrustScanResult> {
    const allPatterns = [...new Set(ZT_RULES.flatMap((r) => r.filePatterns))];
    const files = await glob(allPatterns, {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
      nodir: true,
    });

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of ZT_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            if (pattern.test(lines[i])) {
              findings.push({
                id: `ZT-${String(idCounter++).padStart(4, "0")}`,
                rule: `zt:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "zero-trust",
                cwe: rule.cwe,
                confidence: "high",
                location: {
                  file: relativePath,
                  line: i + 1,
                  snippet: lines[i].trim(),
                },
              });
            }
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
