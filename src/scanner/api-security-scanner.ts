import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface ApiRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  owasp?: string;
  patterns: RegExp[];
}

const API_RULES: ApiRule[] = [
  // BOLA / IDOR
  {
    id: "api-bola-idor",
    title: "API: Broken Object Level Authorization (BOLA/IDOR)",
    description:
      "Object accessed by user-supplied ID without ownership verification. An attacker can access other users' data by changing the ID.",
    severity: "critical",
    cwe: "CWE-639",
    owasp: "API1:2023",
    patterns: [
      /\.findById\s*\(\s*req\.params\.\w+\s*\)(?!.*(?:userId|ownerId|createdBy|where))/gi,
      /\.findOne\s*\(\s*\{\s*(?:_id|id)\s*:\s*req\.params/gi,
      /\.findByPk\s*\(\s*req\.params/gi,
    ],
  },

  // Broken Authentication
  {
    id: "api-broken-auth",
    title: "API: Broken Authentication",
    description:
      "JWT or session configuration missing security settings (expiry, rotation, or secure flags).",
    severity: "high",
    cwe: "CWE-287",
    owasp: "API2:2023",
    patterns: [
      /jwt\.sign\s*\((?!.*expiresIn)(?!.*exp)/gi,
      /createToken\s*\((?!.*expir)/gi,
      /session\s*\(\s*\{(?!.*(?:maxAge|expires|rolling))/gi,
    ],
  },

  // Excessive Data Exposure
  {
    id: "api-data-exposure",
    title: "API: Excessive Data Exposure",
    description:
      "Full database object returned in API response. May leak sensitive fields (password, internal IDs, tokens).",
    severity: "high",
    cwe: "CWE-213",
    owasp: "API3:2023",
    patterns: [
      /res\.json\s*\(\s*(?:user|account|profile|customer|employee)\s*\)/gi,
      /res\.send\s*\(\s*(?:user|account|profile|customer)\s*\)/gi,
      /return\s+(?:user|account|customer)\s*;?\s*$/gm,
    ],
  },

  // Mass Assignment
  {
    id: "api-mass-assignment",
    title: "API: Mass Assignment",
    description:
      "Request body passed directly to database create/update. Attacker can set admin flags, IDs, or other protected fields.",
    severity: "high",
    cwe: "CWE-915",
    owasp: "API6:2023",
    patterns: [
      /\.create\s*\(\s*req\.body\s*\)/gi,
      /\.update\s*\(\s*req\.body\s*\)/gi,
      /\.findOneAndUpdate\s*\([^,]*,\s*req\.body/gi,
      /\.insertOne\s*\(\s*req\.body\s*\)/gi,
      /Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)/gi,
    ],
  },

  // Missing Rate Limiting
  {
    id: "api-no-rate-limit",
    title: "API: No Rate Limiting on Sensitive Endpoint",
    description:
      "Login, registration, or password reset endpoint without rate limiting. Enables brute-force attacks.",
    severity: "medium",
    cwe: "CWE-307",
    owasp: "API4:2023",
    patterns: [
      /\.post\s*\(\s*['"]\/(?:login|signin|auth|register|signup|reset|forgot)['"](?!.*(?:rateLimit|rateLimiter|throttle|limiter))/gi,
    ],
  },

  // No Input Validation
  {
    id: "api-no-validation",
    title: "API: No Input Validation Schema",
    description:
      "API endpoint handler uses req.body without schema validation (joi, zod, yup). Unexpected input can cause errors or exploits.",
    severity: "medium",
    cwe: "CWE-20",
    owasp: "API8:2023",
    patterns: [
      /(?:app|router)\.(?:post|put|patch)\s*\([^)]*(?:req\s*,\s*res|request\s*,\s*response)(?!.*(?:validate|schema|joi|zod|yup|ajv|celebrate))/gi,
    ],
  },

  // Broken Function-Level Authorization
  {
    id: "api-broken-function-auth",
    title: "API: Admin Endpoint Without Role Check",
    description:
      "Endpoint with admin/management path does not appear to check user role or permissions.",
    severity: "high",
    cwe: "CWE-285",
    owasp: "API5:2023",
    patterns: [
      /\.(?:get|post|put|delete)\s*\(\s*['"]\/(?:admin|manage|internal|system|config)(?!.*(?:isAdmin|requireAdmin|checkRole|authorize|permission|rbac))/gi,
    ],
  },

  // SSRF via API
  {
    id: "api-ssrf",
    title: "API: Server-Side Request Forgery via URL Parameter",
    description:
      "User-supplied URL passed to server-side HTTP request. Attacker can probe internal services or cloud metadata.",
    severity: "high",
    cwe: "CWE-918",
    owasp: "API10:2023",
    patterns: [
      /(?:fetch|axios|got|request|http\.get)\s*\(\s*req\.(?:query|body|params)\.\w+/gi,
      /(?:fetch|axios)\s*\(\s*`\$\{req\.(?:query|body|params)/gi,
    ],
  },

  // Logging Sensitive Data
  {
    id: "api-log-sensitive",
    title: "API: Logging Sensitive Data",
    description:
      "Request body or headers logged to console. May expose passwords, tokens, or PII in log files.",
    severity: "medium",
    cwe: "CWE-532",
    patterns: [
      /console\.log\s*\(\s*req\.body\s*\)/gi,
      /console\.log\s*\(\s*req\.headers\s*\)/gi,
      /logger\.(?:info|debug|log)\s*\(\s*req\.body\s*\)/gi,
      /console\.log\s*\(.*(?:password|token|secret|apiKey|authorization)/gi,
    ],
  },

  // No Pagination
  {
    id: "api-no-pagination",
    title: "API: No Pagination on List Endpoint",
    description:
      "Database query returns all records without limit. Enables data dumping and denial of service.",
    severity: "medium",
    cwe: "CWE-770",
    patterns: [
      /\.find\s*\(\s*(?:\{\s*\})?\s*\)(?!.*(?:limit|paginate|take|skip|offset|page))/gi,
      /SELECT\s+\*\s+FROM\s+\w+(?!.*(?:LIMIT|TOP|OFFSET|FETCH))/gi,
    ],
  },

  // Missing Security Headers
  {
    id: "api-missing-headers",
    title: "API: Missing Security Headers",
    description:
      "API does not set security headers. Use Helmet.js or manually set X-Content-Type-Options, X-Frame-Options, etc.",
    severity: "low",
    cwe: "CWE-693",
    patterns: [/app\.use\s*\(\s*express\.json\s*\(\s*\)\s*\)(?![\s\S]{0,500}helmet)/gi],
  },

  // Missing CORS Configuration
  {
    id: "api-cors-wildcard",
    title: "API: CORS Allows All Origins",
    description:
      "CORS configured with wildcard or 'true' origin. Any website can make authenticated requests to your API.",
    severity: "medium",
    cwe: "CWE-942",
    patterns: [
      /cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|\s*['"]?\s*\*\s*['"]?)/gi,
      /Access-Control-Allow-Origin.*\*/gi,
    ],
  },
];

export interface ApiScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class ApiSecurityScanner {
  async scan(projectPath: string): Promise<ApiScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py", "**/*.go", "**/*.java"],
      {
        cwd: projectPath,
        absolute: true,
        ignore: [
          "node_modules/**",
          "dist/**",
          ".git/**",
          ".sphinx/**",
          "**/*.test.*",
          "**/*.spec.*",
        ],
        nodir: true,
      }
    );

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

      // Quick check: skip files that don't look like API handlers
      if (
        !/(?:app|router|server)\.|express|fastify|koa|hono|flask|gin|spring|req\.|request\./i.test(
          content
        )
      ) {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of API_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            if (pattern.test(lines[i])) {
              findings.push({
                id: `API-${String(idCounter++).padStart(4, "0")}`,
                rule: `api:${rule.id}`,
                title: rule.title,
                description: rule.description + (rule.owasp ? ` (${rule.owasp})` : ""),
                severity: rule.severity,
                category: "api-security",
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
