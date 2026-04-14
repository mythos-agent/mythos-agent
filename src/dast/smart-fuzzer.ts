import Anthropic from "@anthropic-ai/sdk";
import type { SphinxConfig, Vulnerability, Severity } from "../types/index.js";

export interface SmartFuzzResult {
  endpoint: string;
  method: string;
  rounds: number;
  findings: Vulnerability[];
  totalPayloadsSent: number;
}

const FUZZ_SYSTEM = `You are an AI-guided fuzzer. Your job is to generate targeted security test payloads based on analysis of an endpoint's code and response behavior.

## Process
1. Analyze the endpoint code to understand expected input format
2. Generate payloads that are syntactically valid but semantically malicious
3. After each round, I'll tell you the response (status code, body, timing)
4. Based on the response, refine your payloads to dig deeper

## Payload Strategy
- Start with detection payloads (identify the vulnerability class)
- Then escalate to exploitation payloads (prove the impact)
- Adapt to WAF/filters: try encoding variations, case changes, nested payloads

## Output Format
{
  "payloads": [
    {
      "param": "name of the parameter to inject",
      "value": "the payload value",
      "method": "GET or POST",
      "reasoning": "why this payload should trigger a vulnerability",
      "expectedIndicator": "what to look for in the response"
    }
  ],
  "analysis": "your analysis of previous round results (if any)",
  "nextStrategy": "what you'll try if these don't work"
}`;

const MAX_ROUNDS = 5;
const MAX_PAYLOADS_PER_ROUND = 5;

export class SmartFuzzer {
  private client: Anthropic;

  constructor(private config: SphinxConfig) {
    this.client = new Anthropic({ apiKey: config.apiKey });
  }

  /**
   * AI-guided fuzzing with feedback loop.
   * Sends payloads, analyzes responses, generates smarter payloads.
   */
  async fuzz(
    baseUrl: string,
    endpoint: string,
    method: string,
    endpointCode?: string
  ): Promise<SmartFuzzResult> {
    const url = `${baseUrl}${endpoint}`;
    const findings: Vulnerability[] = [];
    let totalPayloads = 0;

    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content: `Fuzz this endpoint for security vulnerabilities:

URL: ${method} ${url}
${endpointCode ? `\nEndpoint code:\n\`\`\`\n${endpointCode}\n\`\`\`` : ""}

Generate your first round of test payloads.`,
      },
    ];

    for (let round = 0; round < MAX_ROUNDS; round++) {
      // Get AI-generated payloads
      const response = await this.client.messages.create({
        model: this.config.model,
        max_tokens: 2048,
        system: FUZZ_SYSTEM,
        messages,
      });

      const text = response.content.find((b) => b.type === "text");
      if (!text || text.type !== "text") break;

      const payloadData = this.parsePayloads(text.text);
      if (!payloadData || payloadData.payloads.length === 0) break;

      // Send payloads and collect results
      const roundResults: string[] = [];

      for (const payload of payloadData.payloads.slice(0, MAX_PAYLOADS_PER_ROUND)) {
        totalPayloads++;
        const result = await this.sendPayload(url, method, payload);
        roundResults.push(
          `Payload: ${payload.param}=${payload.value.slice(0, 50)}\n` +
          `  Status: ${result.status}, Time: ${result.time}ms\n` +
          `  Body preview: ${result.body.slice(0, 200)}`
        );

        // Check if this is a finding
        if (this.isVulnerable(result, payload)) {
          findings.push({
            id: `SFUZZ-${String(findings.length + 1).padStart(4, "0")}`,
            rule: `smart-fuzz:${payload.reasoning.split(" ")[0] || "unknown"}`,
            title: `DAST: ${payload.reasoning.slice(0, 60)}`,
            description: `AI-guided fuzzer confirmed vulnerability at ${method} ${endpoint}.\nPayload: ${payload.value}\nResponse: ${result.status} (${result.time}ms)\nIndicator: ${result.evidence || payload.expectedIndicator}`,
            severity: result.status === 500 ? "high" : "medium",
            category: "dast",
            cwe: "CWE-20",
            confidence: "high",
            location: {
              file: endpoint,
              line: 0,
              snippet: `${method} ${endpoint} — Payload: ${payload.value.slice(0, 60)}`,
            },
          });
        }
      }

      // If we found confirmed vulns, we can stop or continue for more
      if (findings.length > 0 && round >= 2) break;

      // Feed results back to AI for next round
      messages.push({ role: "assistant", content: text.text });
      messages.push({
        role: "user",
        content: `Round ${round + 1} results:\n\n${roundResults.join("\n\n")}\n\n${
          findings.length > 0
            ? `Found ${findings.length} vulnerabilities so far. Generate payloads to escalate/confirm.`
            : "No vulnerabilities confirmed yet. Adjust strategy and try different approaches."
        }`,
      });
    }

    return {
      endpoint,
      method,
      rounds: Math.min(MAX_ROUNDS, totalPayloads > 0 ? Math.ceil(totalPayloads / MAX_PAYLOADS_PER_ROUND) : 0),
      findings,
      totalPayloadsSent: totalPayloads,
    };
  }

  private async sendPayload(
    url: string,
    method: string,
    payload: { param: string; value: string; method?: string }
  ): Promise<{ status: number; time: number; body: string; evidence?: string }> {
    const start = Date.now();
    const actualMethod = payload.method || method;

    const targetUrl = actualMethod === "GET"
      ? `${url}?${payload.param}=${encodeURIComponent(payload.value)}`
      : url;

    const body = ["POST", "PUT", "PATCH"].includes(actualMethod)
      ? JSON.stringify({ [payload.param]: payload.value })
      : undefined;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(targetUrl, {
        method: actualMethod,
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "sphinx-agent/1.0 (security-scanner)",
        },
        body,
        signal: controller.signal,
        redirect: "manual",
      });

      clearTimeout(timer);
      const responseBody = await response.text().catch(() => "");
      const time = Date.now() - start;

      return { status: response.status, time, body: responseBody };
    } catch {
      return { status: 0, time: Date.now() - start, body: "" };
    }
  }

  private isVulnerable(
    result: { status: number; time: number; body: string },
    payload: { expectedIndicator: string; value: string }
  ): boolean {
    // Server error with database error messages
    if (result.status === 500 && /sql|syntax|query|database|error|exception/i.test(result.body)) {
      return true;
    }

    // Reflected XSS
    if (result.body.includes(payload.value) && /<script|onload|onerror|onclick/i.test(payload.value)) {
      return true;
    }

    // Time-based blind injection (response > 4.5s)
    if (result.time > 4500 && payload.value.includes("WAITFOR")) {
      return true;
    }

    // Check expected indicator
    if (payload.expectedIndicator && new RegExp(payload.expectedIndicator, "i").test(result.body)) {
      return true;
    }

    return false;
  }

  private parsePayloads(text: string): {
    payloads: Array<{
      param: string;
      value: string;
      method?: string;
      reasoning: string;
      expectedIndicator: string;
    }>;
  } | null {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;
    try {
      return JSON.parse(jsonMatch[0]);
    } catch {
      return null;
    }
  }
}
