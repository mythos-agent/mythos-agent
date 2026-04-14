import type { RuleDefinition } from "../types/index.js";

/**
 * Framework-specific security rules.
 * These detect vulnerabilities specific to popular frameworks.
 */
export function loadFrameworkRules(): RuleDefinition[] {
  return [
    // === React / Next.js ===
    {
      id: "react-href-injection",
      title: "React: Unvalidated href in anchor tag",
      description: "User input in href can lead to javascript: protocol XSS. Validate URLs.",
      severity: "high",
      category: "xss",
      cwe: "CWE-79",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "<a[^>]*href\\s*=\\s*\\{.*(?:req|params|query|input|user|data)" },
      ],
    },
    {
      id: "next-exposed-env",
      title: "Next.js: Secret in NEXT_PUBLIC_ env var",
      description: "NEXT_PUBLIC_ vars are exposed to the browser. Do not put secrets in them.",
      severity: "high",
      category: "secrets",
      cwe: "CWE-200",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "NEXT_PUBLIC_.*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)" },
      ],
    },
    {
      id: "next-unsafe-redirect",
      title: "Next.js: Unvalidated redirect destination",
      description: "User input used in redirect() without validation. Use a whitelist.",
      severity: "medium",
      category: "redirect",
      cwe: "CWE-601",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "redirect\\s*\\(.*(?:req|params|query|searchParams)" },
      ],
    },
    {
      id: "react-ref-dom-xss",
      title: "React: Direct DOM manipulation via ref",
      description: "Setting innerHTML via ref bypasses React's XSS protection.",
      severity: "high",
      category: "xss",
      cwe: "CWE-79",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "ref\\.current\\.innerHTML\\s*=" },
      ],
    },

    // === Express.js ===
    {
      id: "express-no-helmet",
      title: "Express: Missing security headers (no Helmet)",
      description: "Express app without Helmet middleware is missing critical security headers.",
      severity: "medium",
      category: "config",
      cwe: "CWE-693",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "express\\(\\)" },
      ],
    },
    {
      id: "express-session-insecure",
      title: "Express: Session with insecure defaults",
      description: "Session cookie missing secure/httpOnly/sameSite flags.",
      severity: "medium",
      category: "auth",
      cwe: "CWE-614",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "session\\(\\s*\\{[^}]*secret\\s*:" },
      ],
    },
    {
      id: "express-cors-wildcard",
      title: "Express: CORS allows all origins",
      description: "CORS with wildcard origin allows any site to make requests to your API.",
      severity: "medium",
      category: "config",
      cwe: "CWE-942",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "cors\\(\\s*\\{[^}]*origin\\s*:\\s*(?:true|['\"]\\*['\"])" },
      ],
    },
    {
      id: "express-body-limit",
      title: "Express: No body size limit",
      description: "Missing body parser limit allows large request bodies (DoS risk).",
      severity: "low",
      category: "config",
      cwe: "CWE-770",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "express\\.json\\(\\s*\\)" },
      ],
    },

    // === Django ===
    {
      id: "django-raw-sql",
      title: "Django: Raw SQL query",
      description: "Using raw() or execute() with string formatting. Use parameterized queries.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-89",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "\\.raw\\s*\\(\\s*f['\"]" },
        { type: "regex", pattern: "\\.raw\\s*\\(.*%\\s*" },
        { type: "regex", pattern: "cursor\\.execute\\s*\\(\\s*f['\"]" },
      ],
    },
    {
      id: "django-debug-true",
      title: "Django: DEBUG = True in production",
      description: "DEBUG mode exposes sensitive error information and should be False in production.",
      severity: "high",
      category: "config",
      cwe: "CWE-215",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "DEBUG\\s*=\\s*True" },
      ],
    },
    {
      id: "django-csrf-exempt",
      title: "Django: CSRF protection disabled",
      description: "csrf_exempt decorator disables CSRF protection. Ensure this is intentional.",
      severity: "medium",
      category: "auth",
      cwe: "CWE-352",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "@csrf_exempt" },
      ],
    },
    {
      id: "django-mark-safe",
      title: "Django: mark_safe with user input",
      description: "mark_safe() bypasses auto-escaping. User input could lead to XSS.",
      severity: "high",
      category: "xss",
      cwe: "CWE-79",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "mark_safe\\s*\\(.*(?:request|input|data|param)" },
      ],
    },
    {
      id: "django-secret-key-exposed",
      title: "Django: SECRET_KEY hardcoded",
      description: "SECRET_KEY should be loaded from environment variables, not hardcoded.",
      severity: "high",
      category: "secrets",
      cwe: "CWE-798",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "SECRET_KEY\\s*=\\s*['\"][^'\"]{10,}['\"]" },
      ],
    },

    // === Flask ===
    {
      id: "flask-debug-mode",
      title: "Flask: Debug mode enabled",
      description: "Debug mode enables the interactive debugger which allows arbitrary code execution.",
      severity: "critical",
      category: "config",
      cwe: "CWE-215",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "app\\.run\\(.*debug\\s*=\\s*True" },
      ],
    },
    {
      id: "flask-render-string",
      title: "Flask: Server-Side Template Injection",
      description: "render_template_string with user input enables SSTI — arbitrary code execution.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-1336",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "render_template_string\\s*\\(.*(?:request|input|data)" },
      ],
    },
    {
      id: "flask-open-redirect",
      title: "Flask: Unvalidated redirect",
      description: "User input in redirect URL. Validate against whitelist.",
      severity: "medium",
      category: "redirect",
      cwe: "CWE-601",
      languages: ["python"],
      patterns: [
        { type: "regex", pattern: "redirect\\s*\\(\\s*request\\.(?:args|form|values)" },
      ],
    },

    // === Spring Boot (Java) ===
    {
      id: "spring-sqli",
      title: "Spring: SQL Injection via JdbcTemplate",
      description: "String concatenation in JdbcTemplate query. Use parameterized queries.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-89",
      languages: ["java"],
      patterns: [
        { type: "regex", pattern: "jdbcTemplate\\.query\\s*\\(.*\\+" },
      ],
    },
    {
      id: "spring-el-injection",
      title: "Spring: Expression Language Injection",
      description: "User input in SpEL expression enables remote code execution.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-917",
      languages: ["java"],
      patterns: [
        { type: "regex", pattern: "ExpressionParser.*parseExpression.*(?:request|param|input)" },
      ],
    },
    {
      id: "spring-csrf-disabled",
      title: "Spring: CSRF protection disabled",
      description: "Disabling CSRF protection exposes state-changing endpoints to CSRF attacks.",
      severity: "medium",
      category: "auth",
      cwe: "CWE-352",
      languages: ["java"],
      patterns: [
        { type: "regex", pattern: "csrf\\(\\)\\.disable\\(\\)" },
      ],
    },
    {
      id: "spring-cors-allow-all",
      title: "Spring: CORS allows all origins",
      description: "allowedOrigins('*') permits any website to make authenticated requests.",
      severity: "medium",
      category: "config",
      cwe: "CWE-942",
      languages: ["java"],
      patterns: [
        { type: "regex", pattern: 'allowedOrigins\\s*\\(\\s*"\\*"\\s*\\)' },
      ],
    },

    // === Go (Gin/Chi/Echo) ===
    {
      id: "go-template-injection",
      title: "Go: Template Injection",
      description: "User input in template execution enables code execution.",
      severity: "critical",
      category: "injection",
      cwe: "CWE-1336",
      languages: ["go"],
      patterns: [
        { type: "regex", pattern: "template\\.New.*Parse\\(.*(?:request|param|input|r\\.)" },
      ],
    },
    {
      id: "go-insecure-tls",
      title: "Go: Insecure TLS configuration",
      description: "InsecureSkipVerify disables certificate validation. Never use in production.",
      severity: "high",
      category: "crypto",
      cwe: "CWE-295",
      languages: ["go"],
      patterns: [
        { type: "regex", pattern: "InsecureSkipVerify\\s*:\\s*true" },
      ],
    },

    // === General / Cross-framework ===
    {
      id: "prototype-pollution",
      title: "Prototype Pollution via Object Merge",
      description: "Merging user input into objects without sanitization can pollute Object.prototype.",
      severity: "high",
      category: "injection",
      cwe: "CWE-1321",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "Object\\.assign\\s*\\(\\s*\\{\\}.*(?:req|body|params|input)" },
        { type: "regex", pattern: "\\.\\.\\.[^,}]*(?:req\\.body|req\\.query|req\\.params)" },
      ],
    },
    {
      id: "mass-assignment",
      title: "Mass Assignment",
      description: "Passing user input directly to create/update operations allows setting unintended fields.",
      severity: "high",
      category: "access-control",
      cwe: "CWE-915",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "\\.create\\s*\\(\\s*req\\.body\\s*\\)" },
        { type: "regex", pattern: "\\.update\\s*\\(\\s*req\\.body\\s*\\)" },
        { type: "regex", pattern: "\\.findOneAndUpdate\\s*\\([^,]*,\\s*req\\.body" },
      ],
    },
    {
      id: "timing-attack",
      title: "Potential Timing Attack in Comparison",
      description: "Using === for secret comparison leaks information via timing. Use crypto.timingSafeEqual().",
      severity: "medium",
      category: "crypto",
      cwe: "CWE-208",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "(?:token|secret|key|password|hash|signature)\\s*===\\s*" },
      ],
    },
    {
      id: "unhandled-promise",
      title: "Unhandled Promise Rejection",
      description: "Async function without try/catch or .catch() can crash the process on error.",
      severity: "low",
      category: "error-handling",
      cwe: "CWE-755",
      languages: ["typescript", "javascript"],
      patterns: [
        { type: "regex", pattern: "async\\s+\\(.*\\)\\s*=>\\s*\\{(?!.*try)" },
      ],
    },
  ];
}
