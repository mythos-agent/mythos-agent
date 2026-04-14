export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  cwe?: string;
  languages: string[];
  patterns: string[];
}

export const RULES: Rule[] = [
  {
    id: "sql-injection",
    title: "Potential SQL Injection",
    description: "User input concatenated into SQL query. Use parameterized queries.",
    severity: "critical",
    cwe: "CWE-89",
    languages: ["*"],
    patterns: [
      '(?:query|execute|exec|raw)\\s*\\(\\s*[`"\']\\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*\\$\\{',
      '(?:query|execute|exec|raw)\\s*\\(.*\\+.*(?:req\\.|params\\.|body\\.|query\\.)',
      'f"(?:SELECT|INSERT|UPDATE|DELETE).*\\{',
    ],
  },
  {
    id: "xss-unescaped",
    title: "Potential XSS",
    description: "User input rendered without escaping.",
    severity: "high",
    cwe: "CWE-79",
    languages: ["typescript", "javascript"],
    patterns: ["dangerouslySetInnerHTML", "\\.innerHTML\\s*=", "document\\.write\\s*\\("],
  },
  {
    id: "command-injection",
    title: "Potential Command Injection",
    description: "User input in shell command. Use safe APIs.",
    severity: "critical",
    cwe: "CWE-78",
    languages: ["*"],
    patterns: [
      '(?:exec|execSync|spawn|spawnSync)\\s*\\(.*(?:\\+|\\$\\{).*(?:req\\.|params\\.|body\\.|input|user)',
      "child_process.*exec\\s*\\(\\s*`",
    ],
  },
  {
    id: "path-traversal",
    title: "Potential Path Traversal",
    description: "User input in file path. Validate and normalize.",
    severity: "high",
    cwe: "CWE-22",
    languages: ["*"],
    patterns: [
      "(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream)\\s*\\(.*(?:req\\.|params\\.|body\\.|query\\.)",
    ],
  },
  {
    id: "hardcoded-secret",
    title: "Hardcoded Secret",
    description: "Secret or API key hardcoded. Use environment variables.",
    severity: "high",
    cwe: "CWE-798",
    languages: ["*"],
    patterns: [
      '(?:password|passwd|pwd|secret|api_?key|apikey|token|auth_?token)\\s*[:=]\\s*["\'][^"\'\\s]{8,}["\']',
    ],
  },
  {
    id: "weak-crypto",
    title: "Weak Cryptographic Algorithm",
    description: "Use modern algorithms (SHA-256, AES-256).",
    severity: "medium",
    cwe: "CWE-327",
    languages: ["*"],
    patterns: ["createHash\\s*\\(\\s*['\"](?:md5|sha1|md4)['\"]"],
  },
  {
    id: "eval-usage",
    title: "Dangerous eval()",
    description: "eval() executes arbitrary code. Avoid with user input.",
    severity: "high",
    cwe: "CWE-95",
    languages: ["typescript", "javascript", "python"],
    patterns: ["\\beval\\s*\\(", "new\\s+Function\\s*\\("],
  },
  {
    id: "nosql-injection",
    title: "Potential NoSQL Injection",
    description: "User input in NoSQL query. Validate input.",
    severity: "high",
    cwe: "CWE-943",
    languages: ["typescript", "javascript"],
    patterns: ["\\.find\\s*\\(\\s*\\{.*(?:req\\.|params\\.|body\\.|query\\.)"],
  },
  {
    id: "ssrf",
    title: "Potential SSRF",
    description: "User input in server-side request URL.",
    severity: "high",
    cwe: "CWE-918",
    languages: ["*"],
    patterns: [
      "(?:fetch|axios|request|got|http\\.get)\\s*\\(.*(?:req\\.|params\\.|body\\.|query\\.|user)",
    ],
  },
  {
    id: "jwt-decode",
    title: "JWT Decode Without Verify",
    description: "jwt.decode() does not verify signatures. Use jwt.verify().",
    severity: "critical",
    cwe: "CWE-345",
    languages: ["*"],
    patterns: ["jwt\\.decode\\s*\\("],
  },
];

export const SECRET_RULES: Rule[] = [
  {
    id: "secret:aws-key",
    title: "AWS Access Key",
    description: "AWS access key found. Rotate immediately.",
    severity: "critical",
    languages: ["*"],
    patterns: ["AKIA[0-9A-Z]{16}"],
  },
  {
    id: "secret:github-pat",
    title: "GitHub Token",
    description: "GitHub token found. Revoke and regenerate.",
    severity: "critical",
    languages: ["*"],
    patterns: ["ghp_[0-9a-zA-Z]{36}"],
  },
  {
    id: "secret:anthropic-key",
    title: "Anthropic API Key",
    description: "Anthropic API key found in source.",
    severity: "critical",
    languages: ["*"],
    patterns: ["sk-ant-api03-[0-9a-zA-Z\\-_]{20,}"],
  },
  {
    id: "secret:stripe-key",
    title: "Stripe Secret Key",
    description: "Stripe secret key found in source.",
    severity: "critical",
    languages: ["*"],
    patterns: ["sk_live_[0-9a-zA-Z]{24,}"],
  },
  {
    id: "secret:private-key",
    title: "Private Key",
    description: "Private key material in source. Never commit keys.",
    severity: "critical",
    languages: ["*"],
    patterns: ["-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"],
  },
  {
    id: "secret:database-url",
    title: "Database Connection String",
    description: "Database URL with credentials found.",
    severity: "critical",
    languages: ["*"],
    patterns: ["(?:postgres|mysql|mongodb|redis)://[^:\\s]+:[^@\\s]+@"],
  },
  {
    id: "secret:generic-key",
    title: "Generic API Key",
    description: "Variable named like an API key with a long value assigned.",
    severity: "high",
    languages: ["*"],
    patterns: [
      '(?:api[_-]?key|api[_-]?secret|auth[_-]?token|secret[_-]?key)\\s*[:=]\\s*["\'][0-9a-zA-Z\\-_./+=]{20,}["\']',
    ],
  },
];
