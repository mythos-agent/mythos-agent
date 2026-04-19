import Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig, Vulnerability, Severity } from "../types/index.js";
import { SYSTEM_PROMPT, buildAnalysisPrompt } from "./prompts.js";
import { createAgentTools, executeToolCall } from "./tools.js";

interface AnalysisResult {
  confirmed: Vulnerability[];
  discovered: Vulnerability[];
  dismissedCount: number;
}

interface VerifiedFinding {
  originalId: string;
  isReal: boolean;
  reasoning: string;
  adjustedSeverity?: Severity;
}

interface DiscoveredFinding {
  title: string;
  description: string;
  severity: Severity;
  category: string;
  cwe?: string;
  file: string;
  line: number;
  snippet?: string;
}

interface AIAnalysisOutput {
  verified: VerifiedFinding[];
  discovered: DiscoveredFinding[];
}

const MAX_TURNS = 20;

export class AIAnalyzer {
  private client: Anthropic;
  private model: string;

  // `client` is optional so tests can inject a scriptable mock that satisfies
  // the Anthropic.Client shape used by the agentic loop without touching
  // the network. Production callers pass `config` only and get a real client.
  constructor(
    private config: MythosConfig,
    client?: Anthropic
  ) {
    this.client = client ?? new Anthropic({ apiKey: config.apiKey });
    this.model = config.model;
  }

  async analyze(projectPath: string, phase1Findings: Vulnerability[]): Promise<AnalysisResult> {
    const tools = createAgentTools(projectPath);
    const userPrompt = buildAnalysisPrompt(phase1Findings, projectPath);

    const messages: Anthropic.MessageParam[] = [{ role: "user", content: userPrompt }];

    // Agentic loop — let the AI call tools until it produces a final answer
    let turns = 0;
    while (turns < MAX_TURNS) {
      turns++;

      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 8192,
        temperature: 0,
        system: SYSTEM_PROMPT,
        tools,
        messages,
      });

      // Check if the model wants to use tools
      if (response.stop_reason === "tool_use") {
        const assistantContent = response.content;
        messages.push({ role: "assistant", content: assistantContent });

        const toolResults: Anthropic.ToolResultBlockParam[] = [];
        for (const block of assistantContent) {
          if (block.type === "tool_use") {
            const result = executeToolCall(
              projectPath,
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

      // Model produced a final answer — extract JSON
      const textBlock = response.content.find((b) => b.type === "text");
      if (textBlock && textBlock.type === "text") {
        return parseAnalysisResponse(textBlock.text, phase1Findings);
      }

      break;
    }

    // Fallback: return all phase1 findings as-is
    return {
      confirmed: phase1Findings,
      discovered: [],
      dismissedCount: 0,
    };
  }
}

/**
 * Parses an AIAnalyzer tool-loop final response into `AnalysisResult`.
 * Exported as a module-level function (not a private method) so tests
 * can hit the verification/dismissal/discovered-id-generation logic
 * without running the 20-turn Anthropic agentic loop.
 *
 * Behavior pinned by src/agent/__tests__/analyzer.test.ts:
 *  - No JSON substring in text → fallback: all phase1 pass through,
 *    dismissedCount=0, discovered=[]. (Load-bearing: if the model
 *    returns prose-only on token-limit truncation, users still get
 *    their phase1 findings back instead of an empty result.)
 *  - Malformed JSON → same fallback, no throw.
 *  - `verified[].isReal=false` → finding is dismissed (dropped from
 *    `confirmed`, incremented in `dismissedCount`).
 *  - `verified[].isReal=true` → finding is kept with
 *    aiVerified=true and confidence="high", and severity is
 *    overridden by `adjustedSeverity` when present.
 *  - phase1 findings with no entry in `verified[]` pass through
 *    unchanged (original confidence, no aiVerified flag).
 *  - `discovered[]` findings get ids SPX-NNNN starting from
 *    phase1.length + 1, rule="ai-discovered", confidence="high",
 *    aiVerified=true.
 */
export function parseAnalysisResponse(
  text: string,
  phase1Findings: Vulnerability[]
): AnalysisResult {
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    return {
      confirmed: phase1Findings,
      discovered: [],
      dismissedCount: 0,
    };
  }

  let output: AIAnalysisOutput;
  try {
    output = JSON.parse(jsonMatch[0]);
  } catch {
    return {
      confirmed: phase1Findings,
      discovered: [],
      dismissedCount: 0,
    };
  }

  const confirmed: Vulnerability[] = [];
  let dismissedCount = 0;

  const verifiedMap = new Map((output.verified || []).map((v) => [v.originalId, v]));

  for (const finding of phase1Findings) {
    const verification = verifiedMap.get(finding.id);
    if (verification) {
      if (verification.isReal) {
        confirmed.push({
          ...finding,
          aiVerified: true,
          severity: verification.adjustedSeverity || finding.severity,
          confidence: "high",
        });
      } else {
        dismissedCount++;
      }
    } else {
      // Not verified by AI — keep with original confidence
      confirmed.push(finding);
    }
  }

  let discoverCounter = phase1Findings.length + 1;
  const discovered: Vulnerability[] = (output.discovered || []).map((d) => ({
    id: `SPX-${String(discoverCounter++).padStart(4, "0")}`,
    rule: "ai-discovered",
    title: d.title,
    description: d.description,
    severity: d.severity,
    category: d.category,
    cwe: d.cwe,
    confidence: "high" as const,
    aiVerified: true,
    location: {
      file: d.file,
      line: d.line,
      snippet: d.snippet,
    },
  }));

  return { confirmed, discovered, dismissedCount };
}
