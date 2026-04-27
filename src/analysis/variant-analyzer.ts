import type Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig, Vulnerability, Severity } from "../types/index.js";
import { type LLMClient, createLLMClient } from "../llm/index.js";
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

You MUST respond with a single JSON object and NOTHING ELSE. No markdown
headers, no prose explanation outside JSON fields, no code fences (no
\`\`\`json wrapper). The first character of your response MUST be '{' and
the last character MUST be '}'. Schema:

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
}

If you find no variants, respond with: {"rootCauseAnalysis": "...", "variants": []}.
Do not respond with prose explaining why you found nothing — the empty
array IS the explanation. The harness parses your output as JSON, and
prose responses produce a 0-variants result that is indistinguishable
from a clean miss.`;

const MAX_TURNS = 20;
const OSV_API = "https://api.osv.dev/v1";

export class VariantAnalyzer {
  private client: LLMClient;

  // Constructed via the multi-model factory so `provider: openai` users
  // (Tier 2 per docs/multi-model.md) get a Qwen / OpenAI / OpenRouter
  // backend just like the four hunt agents do post PRs #44/#46.
  // `client` is optional so tests can inject a scriptable mock; the
  // historical Anthropic type is accepted for back-compat with any
  // pre-multi-model test that constructed an Anthropic mock directly.
  constructor(
    private config: MythosConfig,
    private projectPath: string,
    client?: LLMClient | Anthropic
  ) {
    this.client = (client as LLMClient | undefined) ?? createLLMClient(config);
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
            const result = await executeToolCall(
              this.projectPath,
              block.name,
              block.input as Record<string, unknown>
            );
            toolResults.push({
              type: "tool_result",
              tool_use_id: block.id,
              content: result,
            });
          }
        }
        messages.push({ role: "user", content: toolResults });
        continue;
      }

      const text = response.content.find((b) => b.type === "text");
      if (text && text.type === "text") {
        const variants = parseVariants(text.text, "auto-scan");
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

  /**
   * Run the variant-search agent loop for an externally-supplied
   * `CveInfo` instead of fetching one via OSV/NVD. Used by the A3b
   * calibration harness (see `src/analysis/calibration/agent-runner.ts`)
   * which builds a richer `CveInfo` from A1's seed `RootCausePattern`
   * and bypasses the network round-trip. Equivalent to
   * `findVariants(cveId)` minus step 1.
   */
  async searchForVariants(cveInfo: CveInfo): Promise<VariantMatch[]> {
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
            const result = await executeToolCall(
              this.projectPath,
              block.name,
              block.input as Record<string, unknown>
            );
            toolResults.push({
              type: "tool_result",
              tool_use_id: block.id,
              content: result,
            });
          }
        }
        messages.push({ role: "user", content: toolResults });
        continue;
      }

      const text = response.content.find((b) => b.type === "text");
      if (text && text.type === "text") {
        return parseVariants(text.text, cveInfo.id);
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
}

/**
 * Parses the LLM tool-loop final response into VariantMatch[].
 * Module-level for testability (mirrors the parseAnalysisResponse
 * pattern in src/agent/analyzer.ts) — tests can hit the JSON-parser
 * tolerance without running the 20-turn agentic loop or hitting
 * OSV/NVD over the network.
 *
 * Extraction strategy (most-likely-correct first):
 *
 *  1. **Whole-text parse.** When the system prompt is followed (post
 *     A3b-fix prompt forces JSON-only output), the entire response is
 *     a JSON object. Try parsing it as-is — fastest path, handles the
 *     common case.
 *  2. **Markdown code fences.** If the model emits `\`\`\`json … \`\`\``
 *     blocks, scan each one. This is the second-most-common shape
 *     when prompt instructions partially fail.
 *  3. **Outer-brace regex.** Last resort — greedy `{[\s\S]*\}` match
 *     against the full text. Brittle when prose contains `{` chars,
 *     so it's tried only after the more reliable paths.
 *
 * For every candidate, only accept ones whose parsed JSON has a
 * `variants` ARRAY (not just any `variants` field). That avoids the
 * pre-A3b-fix failure mode where the regex matched a prose `{...}`
 * that happened to contain "variants" elsewhere.
 *
 * Behavior contract:
 *  - No parseable variants object → returns []. Defensive default for
 *    cases where the LLM emits prose-only on token-limit truncation
 *    or refuses for safety reasons.
 *  - Malformed JSON → returns []. NOT a throw; the agentic loop
 *    treats no-variants as a valid (if uninteresting) answer.
 *  - Variants without required fields fall back to defaults
 *    (similarity defaults to "medium", strings to "", numbers to 0).
 *  - VAR-NNN ids start at 001, padded to 3 digits.
 */
export function parseVariants(text: string, cveId: string): VariantMatch[] {
  const candidates = collectJsonCandidates(text);
  for (const candidate of candidates) {
    let data: unknown;
    try {
      data = JSON.parse(candidate);
    } catch {
      continue;
    }
    if (data === null || typeof data !== "object") continue;
    const variantsField = (data as { variants?: unknown }).variants;
    if (!Array.isArray(variantsField)) continue;
    return variantsField.map((v: any, i: number) => ({
      id: `VAR-${String(i + 1).padStart(3, "0")}`,
      cveId,
      file: v?.file || "",
      line: v?.line || 0,
      code: v?.code || "",
      similarity: v?.similarity || "medium",
      explanation: v?.explanation || "",
      rootCauseMatch: v?.rootCauseMatch || "",
    }));
  }
  return [];
}

/**
 * Yield JSON-shaped string candidates from `text`, ordered by
 * likelihood of being the intended payload. Exported for direct
 * testing of the candidate-extraction logic.
 */
export function collectJsonCandidates(text: string): string[] {
  const candidates: string[] = [];
  const trimmed = text.trim();

  // 1. Whole-text parse — covers the post-prompt-fix happy path where
  //    the model returns a single JSON object with no surrounding
  //    prose.
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    candidates.push(trimmed);
  }

  // 2. Markdown code fences — covers the "model added ```json wrapper
  //    despite the instructions" case. The regex tolerates an
  //    optional language tag after the opening fence.
  const fenceRegex = /```(?:json)?\s*\n?([\s\S]*?)```/g;
  for (const match of trimmed.matchAll(fenceRegex)) {
    const body = match[1]?.trim();
    if (body && body.startsWith("{") && body.endsWith("}")) {
      candidates.push(body);
    }
  }

  // 3. Outer-brace regex — last resort for prose-mixed responses.
  //    Greedy match from first `{` to last `}` in the whole text.
  const greedyMatch = trimmed.match(/\{[\s\S]*\}/);
  if (greedyMatch && !candidates.includes(greedyMatch[0])) {
    candidates.push(greedyMatch[0]);
  }

  return candidates;
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
