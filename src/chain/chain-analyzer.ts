import Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig, Vulnerability, VulnChain, Severity } from "../types/index.js";

const CHAIN_PROMPT = `You are a security expert analyzing confirmed vulnerabilities in a codebase. Your job is to identify **vulnerability chains** — sequences of individually exploitable (or seemingly minor) vulnerabilities that, when combined, create a more severe attack path.

## What is a vulnerability chain?

A chain is 2+ vulnerabilities that an attacker can exploit in sequence, where the output/effect of one enables or amplifies the next. Examples:
- SQL Injection → extract credentials → Auth Bypass → access admin panel
- XSS → steal session cookie (due to missing HttpOnly) → Session Hijack → account takeover
- SSRF → access internal metadata → retrieve cloud credentials → full infrastructure compromise
- Path Traversal → read config file → extract DB credentials → data exfiltration

## Instructions

Given the list of confirmed vulnerabilities below, identify any chains. Consider:
1. Can the output of one vulnerability feed into another?
2. Do multiple vulnerabilities affect the same data flow or authentication path?
3. Could individually "medium" issues combine into a "critical" attack path?
4. Are there any privilege escalation paths?

## Output Format

Respond with a JSON object:
{
  "chains": [
    {
      "title": "Short chain title (e.g., 'SQL Injection → Auth Bypass → Data Leak')",
      "severity": "critical|high|medium|low",
      "vulnerabilityIds": ["SPX-0001", "SPX-0003", "SPX-0007"],
      "narrative": "An attacker could... (describe the full attack scenario in 2-3 sentences)",
      "impact": "What damage this chain enables (data theft, account takeover, etc.)"
    }
  ]
}

If no meaningful chains exist, return: { "chains": [] }`;

export class ChainAnalyzer {
  private client: Anthropic;
  private model: string;

  constructor(private config: MythosConfig) {
    this.client = new Anthropic({ apiKey: config.apiKey });
    this.model = config.model;
  }

  async analyzeChains(vulnerabilities: Vulnerability[], projectPath: string): Promise<VulnChain[]> {
    if (!this.config.apiKey || vulnerabilities.length < 2) {
      return [];
    }

    const vulnList = vulnerabilities
      .map(
        (v) =>
          `- ${v.id} [${v.severity.toUpperCase()}] ${v.title}\n  Category: ${v.category} | CWE: ${v.cwe || "N/A"}\n  File: ${v.location.file}:${v.location.line}\n  Code: ${v.location.snippet || "N/A"}\n  Description: ${v.description}`
      )
      .join("\n\n");

    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: 4096,
      system: CHAIN_PROMPT,
      messages: [
        {
          role: "user",
          content: `Analyze these ${vulnerabilities.length} confirmed vulnerabilities for exploitable chains:\n\n${vulnList}`,
        },
      ],
    });

    const textBlock = response.content.find((b) => b.type === "text");
    if (!textBlock || textBlock.type !== "text") return [];

    return this.parseChains(textBlock.text, vulnerabilities);
  }

  private parseChains(text: string, vulnerabilities: Vulnerability[]): VulnChain[] {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return [];

    let output: {
      chains: Array<{
        title: string;
        severity: Severity;
        vulnerabilityIds: string[];
        narrative: string;
        impact: string;
      }>;
    };

    try {
      output = JSON.parse(jsonMatch[0]);
    } catch {
      return [];
    }

    const vulnMap = new Map(vulnerabilities.map((v) => [v.id, v]));

    return (output.chains || [])
      .map((chain, i) => {
        const chainVulns = chain.vulnerabilityIds
          .map((id) => vulnMap.get(id))
          .filter((v): v is Vulnerability => v !== undefined);

        if (chainVulns.length < 2) return null;

        return {
          id: `CHAIN-${String(i + 1).padStart(3, "0")}`,
          title: chain.title,
          severity: chain.severity,
          vulnerabilities: chainVulns,
          narrative: chain.narrative,
          impact: chain.impact,
        };
      })
      .filter((c): c is VulnChain => c !== null);
  }
}
