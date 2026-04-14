import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability } from "../types/index.js";

interface SecretPattern {
  id: string;
  title: string;
  description: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  {
    id: "aws-access-key",
    title: "AWS Access Key ID",
    description: "AWS access key found in source code. Rotate immediately and use environment variables.",
    pattern: /(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])/,
    severity: "critical",
  },
  {
    id: "aws-secret-key",
    title: "AWS Secret Access Key",
    description: "AWS secret key found. Rotate immediately and use AWS Secrets Manager or environment variables.",
    pattern: /(?<![A-Za-z0-9/+=])([0-9a-zA-Z/+=]{40})(?![A-Za-z0-9/+=])(?=.*(?:aws|secret|key))/i,
    severity: "critical",
  },

  // GitHub
  {
    id: "github-pat",
    title: "GitHub Personal Access Token",
    description: "GitHub PAT found in source code. Revoke and regenerate using fine-grained tokens.",
    pattern: /ghp_[0-9a-zA-Z]{36}/,
    severity: "critical",
  },
  {
    id: "github-oauth",
    title: "GitHub OAuth Token",
    description: "GitHub OAuth token found in source code.",
    pattern: /gho_[0-9a-zA-Z]{36}/,
    severity: "critical",
  },
  {
    id: "github-fine-grained",
    title: "GitHub Fine-Grained Token",
    description: "GitHub fine-grained PAT found in source code.",
    pattern: /github_pat_[0-9a-zA-Z_]{82}/,
    severity: "critical",
  },

  // Anthropic / OpenAI
  {
    id: "anthropic-api-key",
    title: "Anthropic API Key",
    description: "Anthropic API key found in source code. Use environment variables.",
    pattern: /sk-ant-api03-[0-9a-zA-Z\-_]{93}/,
    severity: "critical",
  },
  {
    id: "openai-api-key",
    title: "OpenAI API Key",
    description: "OpenAI API key found in source code.",
    pattern: /sk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20}/,
    severity: "critical",
  },
  {
    id: "openai-project-key",
    title: "OpenAI Project API Key",
    description: "OpenAI project key found in source code.",
    pattern: /sk-proj-[0-9a-zA-Z\-_]{100,}/,
    severity: "critical",
  },

  // Stripe
  {
    id: "stripe-secret-key",
    title: "Stripe Secret Key",
    description: "Stripe secret API key found. Use environment variables and restrict key permissions.",
    pattern: /sk_live_[0-9a-zA-Z]{24,}/,
    severity: "critical",
  },
  {
    id: "stripe-publishable-key",
    title: "Stripe Publishable Key",
    description: "Stripe publishable key found in source. This is less sensitive but should still be managed properly.",
    pattern: /pk_live_[0-9a-zA-Z]{24,}/,
    severity: "medium",
  },

  // Google
  {
    id: "google-api-key",
    title: "Google API Key",
    description: "Google API key found in source code. Restrict key usage in Google Cloud Console.",
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
    severity: "high",
  },
  {
    id: "google-oauth-secret",
    title: "Google OAuth Client Secret",
    description: "Google OAuth client secret found in source code.",
    pattern: /GOCSPX-[0-9a-zA-Z\-_]{28}/,
    severity: "critical",
  },

  // Slack
  {
    id: "slack-bot-token",
    title: "Slack Bot Token",
    description: "Slack bot token found in source code.",
    pattern: /xoxb-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{24}/,
    severity: "critical",
  },
  {
    id: "slack-webhook",
    title: "Slack Webhook URL",
    description: "Slack incoming webhook URL found in source code.",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/,
    severity: "high",
  },

  // Database
  {
    id: "database-url",
    title: "Database Connection String",
    description: "Database connection string with credentials found in source code.",
    pattern: /(?:postgres|mysql|mongodb|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s"'`]+/,
    severity: "critical",
  },

  // Private Keys
  {
    id: "private-key",
    title: "Private Key",
    description: "Private key material found in source code. Never commit private keys.",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: "critical",
  },

  // JWT
  {
    id: "jwt-token",
    title: "JSON Web Token",
    description: "A JWT token found in source code. JWTs may contain sensitive claims.",
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    severity: "high",
  },

  // Twilio
  {
    id: "twilio-api-key",
    title: "Twilio API Key",
    description: "Twilio API key found in source code.",
    pattern: /SK[0-9a-fA-F]{32}/,
    severity: "high",
  },

  // SendGrid
  {
    id: "sendgrid-api-key",
    title: "SendGrid API Key",
    description: "SendGrid API key found in source code.",
    pattern: /SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}/,
    severity: "high",
  },

  // npm
  {
    id: "npm-token",
    title: "npm Access Token",
    description: "npm access token found in source code.",
    pattern: /npm_[0-9a-zA-Z]{36}/,
    severity: "critical",
  },

  // Generic high-entropy secrets
  {
    id: "generic-api-key",
    title: "Generic API Key Assignment",
    description: "A variable named like an API key is assigned a long string value. Verify this isn't a real secret.",
    pattern: /(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*[:=]\s*["'][0-9a-zA-Z\-_./+=]{20,}["']/i,
    severity: "high",
  },

  // Password in URL
  {
    id: "password-in-url",
    title: "Password in URL",
    description: "A URL with embedded password found. This may appear in logs and browser history.",
    pattern: /https?:\/\/[^:\s]+:[^@\s]+@[^\s"'`]+/,
    severity: "high",
  },
];

// Files to always scan for secrets regardless of language
const SECRET_FILE_PATTERNS = [
  "**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx",
  "**/*.py", "**/*.go", "**/*.java", "**/*.php",
  "**/*.rb", "**/*.rs", "**/*.cs",
  "**/*.yml", "**/*.yaml", "**/*.json",
  "**/*.toml", "**/*.cfg", "**/*.conf", "**/*.ini",
  "**/*.env", "**/*.env.*",
  "**/*.sh", "**/*.bash",
  "**/Dockerfile*", "**/docker-compose*",
];

const SECRET_EXCLUDE = [
  "node_modules/**", "dist/**", "build/**", ".git/**",
  ".sphinx/**", "**/*.min.js", "**/package-lock.json",
  "**/yarn.lock", "**/*.map",
];

export interface SecretsResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class SecretsScanner {
  async scan(projectPath: string): Promise<SecretsResult> {
    const files = await glob(SECRET_FILE_PATTERNS, {
      cwd: projectPath,
      absolute: true,
      ignore: SECRET_EXCLUDE,
      nodir: true,
    });

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue; // skip large files
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const secret of SECRET_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];

          // Skip comments and obvious non-secret lines
          if (isLikelyFalsePositive(line, relativePath)) continue;

          const match = secret.pattern.exec(line);
          if (match) {
            findings.push({
              id: `SECRET-${String(idCounter++).padStart(4, "0")}`,
              rule: `secret:${secret.id}`,
              title: secret.title,
              description: secret.description,
              severity: secret.severity,
              category: "secrets",
              cwe: "CWE-798",
              confidence: "high",
              location: {
                file: relativePath,
                line: i + 1,
                snippet: maskSecret(line.trim()),
              },
            });
          }
          secret.pattern.lastIndex = 0;
        }
      }
    }

    // Entropy-based detection for .env files
    for (const file of files) {
      const relativePath = path.relative(projectPath, file);
      if (!relativePath.match(/\.env($|\.)/)) continue;

      let content: string;
      try {
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith("#")) continue;

        const eqIdx = line.indexOf("=");
        if (eqIdx === -1) continue;

        const key = line.slice(0, eqIdx).trim();
        const value = line.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "");

        if (value.length >= 8 && isHighEntropy(value) && looksLikeSecret(key)) {
          findings.push({
            id: `SECRET-${String(idCounter++).padStart(4, "0")}`,
            rule: "secret:env-high-entropy",
            title: "High-Entropy Secret in .env File",
            description: `The variable '${key}' contains a high-entropy value that is likely a secret.`,
            severity: "high",
            category: "secrets",
            cwe: "CWE-798",
            confidence: "medium",
            location: {
              file: relativePath,
              line: i + 1,
              snippet: `${key}=${maskSecret(value)}`,
            },
          });
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}

function isLikelyFalsePositive(line: string, filePath: string): boolean {
  const trimmed = line.trim();
  // Skip comments
  if (trimmed.startsWith("//") && !trimmed.includes("=") && !trimmed.includes(":")) return true;
  if (trimmed.startsWith("#") && !trimmed.includes("=")) return true;
  if (trimmed.startsWith("*")) return true;
  // Skip test fixtures / example patterns
  if (filePath.includes("test") || filePath.includes("spec") || filePath.includes("mock")) return true;
  // Skip documentation references
  if (filePath.endsWith(".md")) return true;
  return false;
}

function maskSecret(value: string): string {
  // Show first 4 and last 4 chars, mask the rest
  if (value.length <= 12) return value.slice(0, 3) + "***" + value.slice(-2);
  return value.slice(0, 6) + "..." + value.slice(-4) + " (masked)";
}

function isHighEntropy(str: string): boolean {
  const charset = new Set(str);
  if (charset.size < 6) return false; // too few unique characters

  // Shannon entropy
  const len = str.length;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy > 3.5; // threshold for "looks random"
}

function looksLikeSecret(key: string): boolean {
  const lower = key.toLowerCase();
  const secretWords = [
    "key", "secret", "token", "password", "passwd", "pwd",
    "auth", "credential", "api", "private", "signing",
    "encryption", "database", "db_", "redis", "mongo",
    "stripe", "twilio", "sendgrid", "slack", "webhook",
  ];
  return secretWords.some((w) => lower.includes(w));
}
