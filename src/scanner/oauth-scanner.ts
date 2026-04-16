import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const OAUTH_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "oauth-no-state",
    title: "OAuth: Missing State Parameter",
    description: "OAuth authorization request without state parameter. This enables CSRF attacks on the login flow.",
    severity: "high",
    cwe: "CWE-352",
    patterns: [
      /authorize\?(?![\s\S]{0,200}state=)/gi,
      /\/oauth\/authorize(?![\s\S]{0,200}state)/gi,
      /authorizationUrl(?![\s\S]{0,200}state)/gi,
    ],
  },
  {
    id: "oauth-implicit-flow",
    title: "OAuth: Implicit Flow Used",
    description: "OAuth implicit flow (response_type=token) returns tokens in URL fragment. Use authorization code flow with PKCE.",
    severity: "high",
    cwe: "CWE-319",
    patterns: [
      /response_type\s*[:=]\s*['"]token['"]/gi,
      /response_type=token/gi,
      /implicit\s*[:=]\s*true/gi,
    ],
  },
  {
    id: "oauth-no-pkce",
    title: "OAuth: No PKCE (Proof Key for Code Exchange)",
    description: "OAuth authorization code flow without PKCE. Public clients (SPAs, mobile) must use PKCE to prevent code interception.",
    severity: "medium",
    cwe: "CWE-287",
    patterns: [
      /response_type\s*[:=]\s*['"]code['"](?![\s\S]{0,300}(?:code_challenge|pkce|codeChallenge|codeVerifier))/gi,
    ],
  },
  {
    id: "oauth-token-in-url",
    title: "OAuth: Token in URL Parameter",
    description: "Access token passed as URL query parameter. Tokens in URLs leak via Referer headers, browser history, and logs.",
    severity: "high",
    cwe: "CWE-598",
    patterns: [
      /\?.*access_token=/gi,
      /[?&]token=[^&'"}\s]/gi,
      /url.*\+.*(?:access_token|token|jwt)/gi,
    ],
  },
  {
    id: "oauth-callback-open-redirect",
    title: "OAuth: Open Redirect in Callback URL",
    description: "OAuth redirect_uri not validated against whitelist. Attacker can redirect tokens to their own server.",
    severity: "critical",
    cwe: "CWE-601",
    patterns: [
      /redirect_uri\s*[:=]\s*(?:req\.|params\.|query\.|input)/gi,
      /callback.*url.*req\.(?:query|params|body)/gi,
    ],
  },
  {
    id: "oauth-client-secret-exposed",
    title: "OAuth: Client Secret in Frontend Code",
    description: "OAuth client_secret in client-side code. Client secrets must only exist on the server. Use PKCE for public clients.",
    severity: "critical",
    cwe: "CWE-798",
    patterns: [
      /(?:NEXT_PUBLIC|REACT_APP|VITE).*CLIENT_SECRET/gi,
      /client_secret\s*[:=]\s*['"][^'"]+['"].*(?:fetch|axios|window|document)/gi,
    ],
  },
  {
    id: "oauth-no-token-expiry-check",
    title: "OAuth: No Token Expiry Validation",
    description: "OAuth token used without checking expiration. Expired tokens should be refreshed, not silently accepted.",
    severity: "medium",
    cwe: "CWE-613",
    patterns: [
      /(?:access_token|accessToken)(?![\s\S]{0,300}(?:expires|exp|expir|isExpired|tokenAge))/gi,
    ],
  },
];

export interface OauthScanResult { findings: Vulnerability[]; filesScanned: number; }

export class OauthScanner {
  async scan(projectPath: string): Promise<OauthScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      if (!/oauth|oidc|authorize|token|client_id|client_secret|redirect_uri|passport|auth0|okta|cognito/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of OAUTH_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({ id: `OAUTH-${String(id++).padStart(4, "0")}`, rule: `oauth:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "oauth", cwe: rule.cwe, confidence: "medium", location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" } });
            break;
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
