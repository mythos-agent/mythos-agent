import type { RuleDefinition } from "../types/index.js";

export function loadBuiltinRules(): RuleDefinition[] {
  return [
    // SQL Injection
    {
      id: "sql-injection",
      title: "Potential SQL Injection",
      description:
        "User input appears to be concatenated directly into a SQL query. Use parameterized queries instead.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-89",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern:
            "(?:query|execute|exec|raw)\\s*\\(\\s*[`\"']\\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*\\$\\{",
        },
        {
          type: "regex",
          pattern: "(?:query|execute|exec|raw)\\s*\\(.*\\+.*(?:req\\.|params\\.|body\\.|query\\.)",
        },
        {
          type: "regex",
          pattern: 'f"(?:SELECT|INSERT|UPDATE|DELETE).*\\{',
        },
      ],
    },

    // XSS
    {
      id: "xss-unescaped",
      title: "Potential Cross-Site Scripting (XSS)",
      description:
        "User input appears to be rendered without escaping. Use proper sanitization or escaping.",
      severity: "high",
      category: "xss",
      cwe: "CWE-79",
      languages: ["typescript", "javascript"],
      patterns: [
        {
          type: "regex",
          pattern: "dangerouslySetInnerHTML",
        },
        {
          type: "regex",
          pattern: "\\.innerHTML\\s*=",
        },
        {
          type: "regex",
          pattern: "document\\.write\\s*\\(",
        },
      ],
    },

    // Command Injection
    {
      id: "command-injection",
      title: "Potential Command Injection",
      description:
        "User input may be passed to a shell command. Use safe APIs that avoid shell interpretation.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-78",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern:
            "(?:exec|execSync|spawn|spawnSync)\\s*\\(.*(?:\\+|\\$\\{).*(?:req\\.|params\\.|body\\.|input|user)",
        },
        {
          type: "regex",
          pattern: "child_process.*exec\\s*\\(\\s*`",
        },
        {
          type: "regex",
          pattern:
            '(?:os\\.system|subprocess\\.call|subprocess\\.run|subprocess\\.Popen)\\s*\\(.*(?:f"|\\+|format)',
        },
      ],
    },

    // Path Traversal
    {
      id: "path-traversal",
      title: "Potential Path Traversal",
      description:
        "User input is used in a file path without sanitization. Validate and normalize paths.",
      severity: "high",
      category: "path-traversal",
      cwe: "CWE-22",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern:
            "(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream)\\s*\\(.*(?:req\\.|params\\.|body\\.|query\\.)",
        },
        {
          type: "regex",
          pattern: "path\\.(?:join|resolve)\\s*\\(.*(?:req\\.|params\\.|body\\.|query\\.)",
        },
        {
          type: "regex",
          pattern: 'open\\s*\\(.*(?:request\\.|f"|format).*(?:r|w|a|rb|wb)',
        },
      ],
    },

    // Hardcoded Secrets
    {
      id: "hardcoded-secret",
      title: "Hardcoded Secret or Credential",
      description:
        "A secret, password, or API key appears to be hardcoded. Use environment variables or a secrets manager.",
      severity: "high",
      category: "secrets",
      cwe: "CWE-798",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern:
            "(?:password|passwd|pwd|secret|api_?key|apikey|token|auth_?token)\\s*[:=]\\s*[\"'][^\"'\\s]{8,}[\"']",
        },
        {
          type: "regex",
          pattern:
            "(?:AWS_SECRET|PRIVATE_KEY|DATABASE_URL|MONGO_URI|REDIS_URL)\\s*[:=]\\s*[\"'][^\"']+[\"']",
        },
      ],
    },

    // Insecure Crypto
    {
      id: "weak-crypto",
      title: "Weak Cryptographic Algorithm",
      description:
        "Use of a weak or broken cryptographic algorithm detected. Use modern alternatives (e.g., SHA-256, AES-256).",
      severity: "medium",
      category: "crypto",
      cwe: "CWE-327",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern: "createHash\\s*\\(\\s*['\"](?:md5|sha1|md4)['\"]",
        },
        {
          type: "regex",
          pattern: "(?:hashlib\\.md5|hashlib\\.sha1|DES\\.|RC4|Blowfish)",
        },
      ],
    },

    // Insecure Cookie
    {
      id: "insecure-cookie",
      title: "Insecure Cookie Configuration",
      description:
        "Cookie is missing security flags. Set httpOnly, secure, and sameSite attributes.",
      severity: "medium",
      category: "auth",
      cwe: "CWE-614",
      languages: ["typescript", "javascript"],
      patterns: [
        {
          type: "regex",
          pattern: "cookie\\s*\\(.*\\{[^}]*(?!httpOnly)[^}]*\\}",
        },
        {
          type: "regex",
          pattern: "set-cookie.*(?!;\\s*httponly)(?!;\\s*secure)",
        },
      ],
    },

    // Eval Usage
    {
      id: "eval-usage",
      title: "Dangerous eval() Usage",
      description:
        "eval() executes arbitrary code and should be avoided, especially with user input.",
      severity: "high",
      category: "injection",
      cwe: "CWE-95",
      languages: ["typescript", "javascript", "python"],
      patterns: [
        {
          type: "regex",
          pattern: "\\beval\\s*\\(",
        },
        {
          type: "regex",
          pattern: "new\\s+Function\\s*\\(",
        },
      ],
    },

    // NoSQL Injection
    {
      id: "nosql-injection",
      title: "Potential NoSQL Injection",
      description: "User input passed directly to a NoSQL query. Use proper input validation.",
      severity: "high",
      category: "injection",
      cwe: "CWE-943",
      languages: ["typescript", "javascript"],
      patterns: [
        {
          type: "regex",
          pattern: "\\.find\\s*\\(\\s*\\{.*(?:req\\.|params\\.|body\\.|query\\.)",
        },
        {
          type: "regex",
          pattern: "\\$where.*(?:req\\.|params\\.|body\\.|query\\.)",
        },
      ],
    },

    // SSRF
    {
      id: "ssrf",
      title: "Potential Server-Side Request Forgery (SSRF)",
      description:
        "User input used in a URL for server-side requests. Validate and restrict allowed destinations.",
      severity: "high",
      category: "ssrf",
      cwe: "CWE-918",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern:
            "(?:fetch|axios|request|got|http\\.get|urllib|requests\\.get)\\s*\\(.*(?:req\\.|params\\.|body\\.|query\\.|user)",
        },
      ],
    },

    // Open Redirect
    {
      id: "open-redirect",
      title: "Potential Open Redirect",
      description:
        "User input used in a redirect URL. Validate redirect destinations against a whitelist.",
      severity: "medium",
      category: "redirect",
      cwe: "CWE-601",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern: "(?:redirect|location)\\s*[=(].*(?:req\\.|params\\.|body\\.|query\\.)",
        },
      ],
    },

    // JWT None Algorithm
    {
      id: "jwt-none-alg",
      title: "JWT None Algorithm Vulnerability",
      description:
        "JWT verification without algorithm restriction can allow forged tokens. Always specify allowed algorithms.",
      severity: "critical",
      category: "auth",
      cwe: "CWE-345",
      languages: ["*"],
      patterns: [
        {
          type: "regex",
          pattern: "jwt\\.verify\\s*\\([^)]*\\{[^}]*algorithms\\s*:\\s*\\[.*['\"]none['\"]",
        },
        {
          type: "regex",
          pattern: "jwt\\.decode\\s*\\(",
        },
      ],
    },

    // === Go-specific rules ===

    {
      id: "go-sql-injection",
      title: "Potential SQL Injection (Go)",
      description:
        "String concatenation or fmt.Sprintf used in SQL query. Use parameterized queries with $1, $2 placeholders.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-89",
      languages: ["go"],
      patterns: [
        {
          type: "regex",
          pattern: 'db\\.(?:Query|Exec|QueryRow)\\s*\\(\\s*(?:fmt\\.Sprintf|"[^"]*"\\s*\\+)',
        },
        {
          type: "regex",
          pattern: 'fmt\\.Sprintf\\s*\\(\\s*"(?:SELECT|INSERT|UPDATE|DELETE)',
        },
      ],
    },

    {
      id: "go-command-injection",
      title: "Potential Command Injection (Go)",
      description:
        "User input may be passed to os/exec. Use exec.Command with separate arguments instead of shell execution.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-78",
      languages: ["go"],
      patterns: [
        {
          type: "regex",
          pattern: 'exec\\.Command\\s*\\(\\s*"(?:sh|bash|cmd)"\\s*,\\s*"-c"',
        },
      ],
    },

    {
      id: "go-hardcoded-credential",
      title: "Hardcoded Credential (Go)",
      description:
        "Credentials appear to be hardcoded. Use environment variables or a secrets manager.",
      severity: "high",
      category: "secrets",
      cwe: "CWE-798",
      languages: ["go"],
      patterns: [
        {
          type: "regex",
          pattern: '(?:password|secret|apiKey|token)\\s*(?::=|=)\\s*"[^"]{8,}"',
        },
      ],
    },

    // === Java-specific rules ===

    {
      id: "java-sql-injection",
      title: "Potential SQL Injection (Java)",
      description:
        "String concatenation in SQL query. Use PreparedStatement with parameterized queries.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-89",
      languages: ["java"],
      patterns: [
        {
          type: "regex",
          pattern: '(?:createStatement|executeQuery|executeUpdate)\\s*\\(\\s*".*"\\s*\\+',
        },
        {
          type: "regex",
          pattern: "Statement.*execute.*\\+.*(?:request|param|input|user)",
        },
      ],
    },

    {
      id: "java-xxe",
      title: "Potential XML External Entity (XXE)",
      description:
        "XML parser without disabled external entities. Disable DTDs and external entities.",
      severity: "high",
      category: "injection",
      cwe: "CWE-611",
      languages: ["java"],
      patterns: [
        {
          type: "regex",
          pattern: "DocumentBuilderFactory\\.newInstance\\(\\)",
        },
        {
          type: "regex",
          pattern: "SAXParserFactory\\.newInstance\\(\\)",
        },
        {
          type: "regex",
          pattern: "XMLInputFactory\\.newInstance\\(\\)",
        },
      ],
    },

    {
      id: "java-deserialization",
      title: "Potential Insecure Deserialization (Java)",
      description:
        "ObjectInputStream.readObject() can execute arbitrary code. Use safe deserialization libraries.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-502",
      languages: ["java"],
      patterns: [
        {
          type: "regex",
          pattern: "\\.readObject\\s*\\(\\)",
        },
      ],
    },

    {
      id: "java-weak-crypto",
      title: "Weak Cryptography (Java)",
      description: "Use of weak cryptographic algorithm. Use AES-256, SHA-256 or better.",
      severity: "medium",
      category: "crypto",
      cwe: "CWE-327",
      languages: ["java"],
      patterns: [
        {
          type: "regex",
          pattern: 'Cipher\\.getInstance\\s*\\(\\s*"(?:DES|RC4|Blowfish|RC2)',
        },
        {
          type: "regex",
          pattern: 'MessageDigest\\.getInstance\\s*\\(\\s*"(?:MD5|SHA-1|SHA1)"',
        },
      ],
    },

    // === PHP-specific rules ===

    {
      id: "php-sql-injection",
      title: "Potential SQL Injection (PHP)",
      description: "User input in SQL query. Use prepared statements with PDO or mysqli.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-89",
      languages: ["php"],
      patterns: [
        {
          type: "regex",
          pattern: "(?:mysql_query|mysqli_query|pg_query)\\s*\\(.*\\$_(?:GET|POST|REQUEST|COOKIE)",
        },
        {
          type: "regex",
          pattern: "\\$.*->query\\s*\\(.*\\$_(?:GET|POST|REQUEST)",
        },
      ],
    },

    {
      id: "php-xss",
      title: "Potential XSS (PHP)",
      description: "User input echoed without escaping. Use htmlspecialchars() or htmlentities().",
      severity: "high",
      category: "xss",
      cwe: "CWE-79",
      languages: ["php"],
      patterns: [
        {
          type: "regex",
          pattern: "echo\\s+\\$_(?:GET|POST|REQUEST|COOKIE)",
        },
        {
          type: "regex",
          pattern: "print\\s+\\$_(?:GET|POST|REQUEST)",
        },
      ],
    },

    {
      id: "php-command-injection",
      title: "Potential Command Injection (PHP)",
      description: "User input in shell command. Use escapeshellarg() and escapeshellcmd().",
      severity: "critical",
      category: "injection",
      cwe: "CWE-78",
      languages: ["php"],
      patterns: [
        {
          type: "regex",
          pattern: "(?:exec|system|passthru|shell_exec|popen)\\s*\\(.*\\$_(?:GET|POST|REQUEST)",
        },
        {
          type: "regex",
          pattern: "`.*\\$_(?:GET|POST|REQUEST)",
        },
      ],
    },

    {
      id: "php-file-inclusion",
      title: "Potential File Inclusion (PHP)",
      description: "User input in include/require. This can lead to remote code execution.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-98",
      languages: ["php"],
      patterns: [
        {
          type: "regex",
          pattern: "(?:include|require|include_once|require_once)\\s*\\(.*\\$_(?:GET|POST|REQUEST)",
        },
      ],
    },

    {
      id: "php-eval",
      title: "Dangerous eval() Usage (PHP)",
      description:
        "eval() executes arbitrary PHP code. Avoid using eval() especially with user input.",
      severity: "high",
      category: "injection",
      cwe: "CWE-95",
      languages: ["php"],
      patterns: [
        {
          type: "regex",
          pattern: "eval\\s*\\(.*\\$",
        },
      ],
    },
  ];
}
