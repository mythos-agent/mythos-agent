import Anthropic from "@anthropic-ai/sdk";
import type { SphinxConfig, Vulnerability, Severity } from "../types/index.js";
import { createAgentTools, executeToolCall } from "../agent/tools.js";

export interface CveInfo {
  id: string;
  description: string;
  severity: Severity;
  cwe?: string;
  affectedCode?: string;
  rootCause?: string;
}

export interface VariantMatch {
  id: string;
  cveId: string;
  file: string;
  line: number;
  code: string;
  similarity: "high" | "medium" | "low";
  explanation: string;
  rootCauseMatch: string;
}

const VARIANT_SYSTEM = `You are a variant analysis engine, inspired by Google's Big Sleep project. Given a known CVE (vulnerability), you find STRUCTURALLY SIMILAR but SYNTACTICALLY DIFFERENT code in the target codebase.

## How Variant Analysis Works

1. Extract the ROOT CAUSE of the known vulnerability (not the surface pattern)
   - Example: CVE describes "buffer overflow in URL parser" → root cause is "length not checked before copy into fixed-size buffer"
2. Search the codebase for code that shares the SAME ROOT CAUSE
   - Same type of mistake, different function, different variable names
3. Rate similarity: high (same root cause + same data flow), medium (same root cause, different context), low (similar pattern, unclear if exploitable)

## Key Insight
Don't match surface syntax. Match the UNDERLYING MISTAKE. A buffer overflow in a URL parser and a buffer overflow in a JSON parser have the same root cause pattern even though the code looks completely different.

## Output Format
{
  "rootCauseAnalysis": "Description of the root cause pattern extracted from the CVE",
  "variants": [
    {
      "file": "src/parser.ts",
      "line": 42,
      "code": "the matching code snippet",
      "similarity": "high",
      "explanation": "This code has the same root cause: user-controlled length passed to buffer allocation without bounds check",
      "rootCauseMatch": "Unchecked length → buffer allocation"
    }
  ]
}`;

const MAX_TURNS = 20;
const OSV_API = "https://api.osv.dev/v1";

export class VariantAnalyzer {
  private client: Anthropic;

  constructor(
    private config: SphinxConfig,
    private projectPath: string
  ) {
    this.client = new Anthropic({ apiKey: config.apiKey });
  }

  /**
   * Analyze a specific CVE and find variants in the codebase.
   */
  async findVariants(cveId: string): Promise<VariantMatch[]> {
    // Step 1: Fetch CVE details
    const cveInfo = await this.fetchCveInfo(cveId);
    if (!cveInfo) {
      return [];
    }

    // Step 2: Use AI to find variants in the codebase
    return this.searchForVariants(cveInfo);
  }

  /**
   * Auto-detect project dependencies and scan for variants of their known CVEs.
   */
  async autoScan(): Promise<{ cve: CveInfo; variants: VariantMatch[] }[]> {
    const results: { cve: CveInfo; variants: VariantMatch[] }[] = [];

    // Use AI to identify the project's key patterns and search for common vulnerability variants
    const tools = createAgentTools(this.projectPath);
    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content: `Analyze this codebase for variant vulnerabilities.

1. First, list the project files and understand the tech stack
2. Based on the code patterns you see, identify potential variants of common vulnerability classes:
   - SQL injection variants (template strings, string concatenation, ORM misuse)
   - Auth bypass variants (comparison flaws, token handling, session management)
   - Path traversal variants (URL decode, double encoding, null bytes)
   - Deserialization variants (JSON.parse on user input, eval-like patterns)
   - SSRF variants (URL construction from user input, redirect following)
3. Report any code that structurally resembles a known vulnerability pattern

Output JSON with the same format as variant analysis.`,
      },
    ];

    let turns = 0;
    while (turns < MAX_TURNS) {
      turns++;

      const response = await this.client.messages.create({
        model: this.config.model,
        max_tokens: 8192,
        system: VARIANT_SYSTEM,
        tools,
        messages,
      });

      if (response.stop_reason === "tool_use") {
        messages.push({ role: "assistant", content: response.content });
        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const block of response.content) {
          if (block.type === "tool_use") {
            toolResults.push({
              type: "tool_result",
              tool_use_id: block.id,
              content: executeToolCall(
                this.projectPath,
                block.name,
                block.input as Record<string, unknown>
              ),
            });
          }
        }
        messages.push({ role: "user", content: toolResults });
        continue;
      }

      const text = response.content.find((b) => b.type === "text");
      if (text && text.type === "text") {
        const variants = this.parseVariants(text.text, "auto-scan");
        if (variants.length > 0) {
          results.push({
            cve: {
              id: "auto-scan",
              description: "Automatic variant analysis based on common vulnerability patterns",
              severity: "high",
            },
            variants,
          });
        }
      }
      break;
    }

    return results;
  }

  private async searchForVariants(cveInfo: CveInfo): Promise<VariantMatch[]> {
    const tools = createAgentTools(this.projectPath);

    const prompt = `Find variants of this vulnerability in the target codebase:

CVE: ${cveInfo.id}
Description: ${cveInfo.description}
Severity: ${cveInfo.severity}
${cveInfo.cwe ? `CWE: ${cveInfo.cwe}` : ""}
${cveInfo.rootCause ? `Root Cause: ${cveInfo.rootCause}` : ""}
${cveInfo.affectedCode ? `\nAffected Code Pattern:\n${cveInfo.affectedCode}` : ""}

Instructions:
1. Extract the ROOT CAUSE pattern from this CVE
2. Use the tools to explore the codebase
3. Search for code that shares the same root cause — same type of mistake, different location
4. Report all variants found with similarity ratings`;

    const messages: Anthropic.MessageParam[] = [{ role: "user", content: prompt }];

    let turns = 0;
    while (turns < MAX_TURNS) {
      turns++;

      const response = await this.client.messages.create({
        model: this.config.model,
        max_tokens: 8192,
        system: VARIANT_SYSTEM,
        tools,
        messages,
      });

      if (response.stop_reason === "tool_use") {
        messages.push({ role: "assistant", content: response.content });
        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const block of response.content) {
          if (block.type === "tool_use") {
            toolResults.push({
              type: "tool_result",
              tool_use_id: block.id,
              content: executeToolCall(
                this.projectPath,
                block.name,
                block.input as Record<string, unknown>
              ),
            });
          }
        }
        messages.push({ role: "user", content: toolResults });
        continue;
      }

      const text = response.content.find((b) => b.type === "text");
      if (text && text.type === "text") {
        return this.parseVariants(text.text, cveInfo.id);
      }
      break;
    }

    return [];
  }

  async fetchCveInfo(cveId: string): Promise<CveInfo | null> {
    // Try OSV API first
    try {
      const response = await fetch(`${OSV_API}/vulns/${cveId}`);
      if (response.ok) {
        const data = (await response.json()) as {
          id: string;
          summary?: string;
          details?: string;
          severity?: Array<{ type: string; score: string }>;
          database_specific?: { cwe_ids?: string[] };
        };

        const cvss = data.severity?.find((s) => s.type === "CVSS_V3");
        const score = cvss ? parseFloat(cvss.score) : 5;
        const severity: Severity =
          score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";

        return {
          id: data.id,
          description: data.summary || data.details || cveId,
          severity,
          cwe: data.database_specific?.cwe_ids?.[0],
        };
      }
    } catch {
      // OSV lookup failed
    }

    // Try NVD API
    try {
      const response = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`
      );
      if (response.ok) {
        const data = (await response.json()) as {
          vulnerabilities?: Array<{
            cve: {
              id: string;
              descriptions?: Array<{ lang: string; value: string }>;
              weaknesses?: Array<{
                description: Array<{ lang: string; value: string }>;
              }>;
              metrics?: {
                cvssMetricV31?: Array<{
                  cvssData: { baseScore: number };
                }>;
              };
            };
          }>;
        };

        const vuln = data.vulnerabilities?.[0]?.cve;
        if (vuln) {
          const desc = vuln.descriptions?.find((d) => d.lang === "en");
          const score = vuln.metrics?.cvssMetricV31?.[0]?.cvssData.baseScore || 5;
          const severity: Severity =
            score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
          const cwe = vuln.weaknesses?.[0]?.description?.[0]?.value;

          return {
            id: vuln.id,
            description: desc?.value || cveId,
            severity,
            cwe,
          };
        }
      }
    } catch {
      // NVD lookup failed
    }

    return null;
  }

  private parseVariants(text: string, cveId: string): VariantMatch[] {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return [];

    try {
      const data = JSON.parse(jsonMatch[0]);
      return (data.variants || []).map((v: any, i: number) => ({
        id: `VAR-${String(i + 1).padStart(3, "0")}`,
        cveId,
        file: v.file || "",
        line: v.line || 0,
        code: v.code || "",
        similarity: v.similarity || "medium",
        explanation: v.explanation || "",
        rootCauseMatch: v.rootCauseMatch || "",
      }));
    } catch {
      return [];
    }
  }
}

/**
 * Convert variant matches to vulnerability findings.
 */
export function variantsToVulnerabilities(
  variants: VariantMatch[],
  cveInfo: CveInfo
): Vulnerability[] {
  return variants.map((v) => ({
    id: v.id,
    rule: `variant:${v.cveId}`,
    title: `[Variant] Similar to ${v.cveId}: ${v.rootCauseMatch}`,
    description: `This code shares the same root cause as ${v.cveId}. ${v.explanation}`,
    severity: cveInfo.severity,
    category: "variant",
    cwe: cveInfo.cwe,
    confidence: (v.similarity === "high" ? "high" : "medium") as "high" | "medium" | "low",
    location: {
      file: v.file,
      line: v.line,
      snippet: v.code,
    },
  }));
}
