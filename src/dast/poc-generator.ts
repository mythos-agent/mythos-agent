import Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig, Vulnerability } from "../types/index.js";

export interface ProofOfConcept {
  vulnerabilityId: string;
  title: string;
  description: string;
  curlCommand?: string;
  pythonScript?: string;
  httpRequest?: string;
  expectedResult: string;
  impact: string;
  verified: boolean;
}

const POC_SYSTEM = `You are a security proof-of-concept generator. Given a confirmed vulnerability, generate a MINIMAL exploit that demonstrates the issue.

## Requirements
- Generate a curl command (always) + Python script (when complex)
- The PoC should be SAFE — demonstrate the vulnerability without causing damage
- Include expected output so the user can verify
- Explain the impact clearly

## Output Format
{
  "title": "PoC: SQL Injection in /api/search",
  "description": "Demonstrates extracting database version via error-based SQL injection",
  "curlCommand": "curl -s 'http://target/api/search?q=%27%20UNION%20SELECT%20version()--'",
  "pythonScript": "import requests\\nresp = requests.get('http://target/api/search', params={'q': \"' UNION SELECT version()--\"})\\nprint(resp.text)",
  "httpRequest": "GET /api/search?q=%27+UNION+SELECT+version()-- HTTP/1.1\\nHost: target",
  "expectedResult": "Response contains database version string (e.g., 'PostgreSQL 15.2')",
  "impact": "Attacker can extract arbitrary data from the database including user credentials"
}`;

export class PocGenerator {
  private client: Anthropic;

  // `client` is optional so tests can inject a scriptable mock via
  // createMockClient (src/__tests__/llm-mock.ts).
  constructor(
    private config: MythosConfig,
    client?: Anthropic
  ) {
    this.client = client ?? new Anthropic({ apiKey: config.apiKey });
  }

  async generate(vulnerability: Vulnerability, targetUrl?: string): Promise<ProofOfConcept> {
    const target = targetUrl || "http://localhost:3000";

    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: 2048,
      system: POC_SYSTEM,
      messages: [
        {
          role: "user",
          content: `Generate a proof-of-concept exploit for this vulnerability:

ID: ${vulnerability.id}
Title: ${vulnerability.title}
Description: ${vulnerability.description}
Severity: ${vulnerability.severity}
CWE: ${vulnerability.cwe || "N/A"}
File: ${vulnerability.location.file}:${vulnerability.location.line}
Code: ${vulnerability.location.snippet || "N/A"}

Target URL: ${target}

Generate a minimal, safe PoC that proves the vulnerability exists.`,
        },
      ],
    });

    const text = response.content.find((b) => b.type === "text");
    if (!text || text.type !== "text") {
      return {
        vulnerabilityId: vulnerability.id,
        title: `PoC for ${vulnerability.title}`,
        description: "Could not generate PoC",
        expectedResult: "N/A",
        impact: vulnerability.description,
        verified: false,
      };
    }

    return parsePoc(text.text, vulnerability.id);
  }

  /**
   * Generate PoCs for multiple vulnerabilities in batch.
   */
  async generateBatch(
    vulnerabilities: Vulnerability[],
    targetUrl?: string
  ): Promise<ProofOfConcept[]> {
    const pocs: ProofOfConcept[] = [];

    // Only generate PoCs for high/critical findings
    const significant = vulnerabilities.filter(
      (v) => v.severity === "critical" || v.severity === "high"
    );

    for (const vuln of significant.slice(0, 10)) {
      try {
        const poc = await this.generate(vuln, targetUrl);
        pocs.push(poc);
      } catch {
        // Skip failed PoC generation
      }
    }

    return pocs;
  }
}

/**
 * Parse a Claude PoC-generation response into `ProofOfConcept` shape.
 * Exported so tests can exercise the JSON-extraction + field-defaulting
 * + malformed-input fallback without running the AI call.
 *
 * Three disjoint return shapes:
 *   - No JSON substring → "PoC generation failed" sentinel, first
 *     200 chars of text as description, expectedResult/impact "N/A".
 *   - JSON parse error → "PoC parse failed" sentinel (same shape
 *     as above but different title).
 *   - Valid JSON → mapped ProofOfConcept with per-field defaults
 *     (title="PoC for <id>", description="", expectedResult="",
 *     impact="") for missing keys. verified is always false — the
 *     fuzzer verifies separately.
 */
export function parsePoc(text: string, vulnId: string): ProofOfConcept {
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    return {
      vulnerabilityId: vulnId,
      title: "PoC generation failed",
      description: text.slice(0, 200),
      expectedResult: "N/A",
      impact: "N/A",
      verified: false,
    };
  }

  try {
    const data = JSON.parse(jsonMatch[0]);
    return {
      vulnerabilityId: vulnId,
      title: data.title || `PoC for ${vulnId}`,
      description: data.description || "",
      curlCommand: data.curlCommand,
      pythonScript: data.pythonScript,
      httpRequest: data.httpRequest,
      expectedResult: data.expectedResult || "",
      impact: data.impact || "",
      verified: false,
    };
  } catch {
    return {
      vulnerabilityId: vulnId,
      title: "PoC parse failed",
      description: text.slice(0, 200),
      expectedResult: "N/A",
      impact: "N/A",
      verified: false,
    };
  }
}
