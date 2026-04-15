import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface PrivacyRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  gdpr?: string;
  patterns: RegExp[];
}

const PRIVACY_RULES: PrivacyRule[] = [
  {
    id: "privacy-pii-logging",
    title: "Privacy: PII Logged to Console/Files",
    description: "Personal data (email, name, SSN, phone) is logged. This violates data minimization principles and GDPR Art. 5.",
    severity: "high",
    cwe: "CWE-532",
    gdpr: "Art. 5(1)(c)",
    patterns: [
      /(?:console\.log|logger\.\w+|log\.\w+)\s*\(.*(?:email|phone|ssn|social_security|address|birthday|date_of_birth|creditCard|passport)/gi,
      /(?:console\.log|logger)\s*\(\s*(?:user|customer|patient|employee)\s*\)/gi,
    ],
  },
  {
    id: "privacy-pii-unencrypted",
    title: "Privacy: PII Stored Without Encryption",
    description: "Personal data appears to be stored in a database without encryption. GDPR requires appropriate protection of personal data.",
    severity: "high",
    cwe: "CWE-311",
    gdpr: "Art. 32",
    patterns: [
      /\.(?:create|insert|save)\s*\(\s*\{[^}]*(?:email|phone|ssn|address|dateOfBirth).*(?!.*encrypt)/gi,
    ],
  },
  {
    id: "privacy-no-consent",
    title: "Privacy: Data Collection Without Consent Check",
    description: "User data collected without checking for consent. GDPR requires lawful basis for processing personal data.",
    severity: "medium",
    cwe: "CWE-359",
    gdpr: "Art. 6, Art. 7",
    patterns: [
      /(?:analytics|tracking|telemetry)\.\w+\s*\((?!.*(?:consent|gdpr|optIn|opt_in|isAllowed))/gi,
      /(?:ga|gtag|fbq|mixpanel|segment)\s*\(\s*['"](?:track|event|identify)/gi,
    ],
  },
  {
    id: "privacy-no-deletion",
    title: "Privacy: No Data Deletion Mechanism",
    description: "No delete/purge endpoint found for user data. GDPR Art. 17 requires the right to erasure.",
    severity: "medium",
    cwe: "CWE-359",
    gdpr: "Art. 17",
    patterns: [
      /\.(?:get|post)\s*\(\s*['"]\/(?:api\/)?(?:user|account|profile)['"](?![\s\S]{0,2000}(?:delete|destroy|remove|purge|erase))/gi,
    ],
  },
  {
    id: "privacy-third-party-data",
    title: "Privacy: User Data Sent to Third-Party",
    description: "User data sent to external service without clear documentation. Requires Data Processing Agreement under GDPR.",
    severity: "medium",
    cwe: "CWE-359",
    gdpr: "Art. 28",
    patterns: [
      /(?:fetch|axios|request)\s*\(.*(?:analytics|tracking|advertising|third.?party).*(?:user|email|name)/gi,
    ],
  },
  {
    id: "privacy-excessive-collection",
    title: "Privacy: Excessive Data Collection",
    description: "Form or API collects more data than needed (SSN, gender, ethnicity). Apply data minimization principle.",
    severity: "low",
    cwe: "CWE-359",
    gdpr: "Art. 5(1)(c)",
    patterns: [
      /(?:required|validate).*(?:gender|ethnicity|race|religion|political|sexual_orientation|marital_status)/gi,
    ],
  },
  {
    id: "privacy-cookie-no-consent",
    title: "Privacy: Cookies Set Without Consent Banner",
    description: "Cookies set on first page load without consent. EU ePrivacy Directive requires consent for non-essential cookies.",
    severity: "medium",
    cwe: "CWE-359",
    gdpr: "ePrivacy Directive",
    patterns: [
      /(?:res\.cookie|document\.cookie)\s*(?:\(|=)(?!.*(?:consent|gdpr|necessary|essential))/gi,
    ],
  },
  {
    id: "privacy-password-plaintext",
    title: "Privacy: Password Stored Without Hashing",
    description: "Password stored or compared in plaintext. Use bcrypt, scrypt, or Argon2 for password hashing.",
    severity: "critical",
    cwe: "CWE-256",
    gdpr: "Art. 32",
    patterns: [
      /password\s*[:=]=?\s*req\.body\.password(?!.*(?:hash|bcrypt|argon|scrypt))/gi,
      /\.create\s*\(\s*\{[^}]*password\s*:\s*(?:req\.body\.password|password)(?!.*hash)/gi,
    ],
  },
  {
    id: "privacy-data-retention",
    title: "Privacy: No Data Retention Policy",
    description: "Data stored indefinitely without TTL or expiry. GDPR requires storage limitation — data should be kept only as long as necessary.",
    severity: "low",
    cwe: "CWE-359",
    gdpr: "Art. 5(1)(e)",
    patterns: [
      /(?:session|token|log|cache).*(?:ttl|expire|maxAge)\s*[:=]\s*(?:0|undefined|null|Infinity)/gi,
    ],
  },
];

export interface PrivacyScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class PrivacyScanner {
  async scan(projectPath: string): Promise<PrivacyScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py"],
      {
        cwd: projectPath,
        absolute: true,
        ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
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
      } catch { continue; }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of PRIVACY_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            if (pattern.test(lines[i])) {
              findings.push({
                id: `PRIV-${String(idCounter++).padStart(4, "0")}`,
                rule: `privacy:${rule.id}`,
                title: rule.title + (rule.gdpr ? ` (GDPR ${rule.gdpr})` : ""),
                description: rule.description,
                severity: rule.severity,
                category: "privacy",
                cwe: rule.cwe,
                confidence: "medium",
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
