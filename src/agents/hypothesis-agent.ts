import Anthropic from "@anthropic-ai/sdk";
import type { SphinxConfig, Vulnerability, Severity } from "../types/index.js";
import { createAgentTools, executeToolCall } from "../agent/tools.js";
import type { ReconReport } from "./agent-protocol.js";

export interface SecurityHypothesis {
  id: string;
  functionName: string;
  file: string;
  line: number;
  hypothesis: string;
  category: string;
  estimatedSeverity: Severity;
  reasoning: string;
  investigationSteps: string[];
}

export interface HypothesisReport {
  type: "hypothesis";
  hypotheses: SecurityHypothesis[];
}

const HYPOTHESIS_SYSTEM = `You are an elite security researcher performing hypothesis-driven vulnerability analysis. Unlike traditional scanners that match known patterns, you REASON about code to identify what COULD go wrong.

For each function you analyze, think like an attacker:
- What assumptions does this code make that could be violated?
- What edge cases are NOT handled?
- What invariants could be broken by malicious input?
- What happens under concurrent access?
- Are there implicit trust relationships that could be exploited?

## Vulnerability Hypothesis Categories

- **input-validation**: Missing bounds checks, type confusion, format string issues
- **auth-bypass**: Paths that skip authentication, weak comparisons, token handling flaws
- **race-condition**: TOCTOU, unprotected shared state, non-atomic operations
- **injection**: Novel injection vectors beyond standard SQLi/XSS
- **crypto-misuse**: Weak randomness, timing attacks, incorrect mode/padding
- **business-logic**: Flaws in application-specific workflows, state machine violations
- **information-disclosure**: Error messages, timing differences, debug endpoints
- **access-control**: IDOR, privilege escalation, missing authorization checks
- **resource-exhaustion**: Unbounded allocations, missing limits, recursive amplification
- **deserialization**: Untrusted data deserialization, prototype pollution, type juggling

## Output Format

For each function, generate 0-3 hypotheses (only meaningful ones). Output JSON:
{
  "hypotheses": [
    {
      "functionName": "processPayment",
      "file": "src/payments.ts",
      "line": 45,
      "hypothesis": "Race condition: concurrent payment requests could double-charge by reading balance before deducting",
      "category": "race-condition",
      "estimatedSeverity": "high",
      "reasoning": "The function reads the account balance and deducts in separate operations without a lock or transaction. Two concurrent requests could both read the same balance and both succeed.",
      "investigationSteps": [
        "Check if database transactions are used around balance read+deduct",
        "Look for any mutex/lock mechanism in the payment flow",
        "Check if the ORM supports optimistic locking on the balance field"
      ]
    }
  ]
}

Only generate hypotheses you have genuine reason to believe based on the code. No generic/template hypotheses.`;

const MAX_TURNS = 20;

export class HypothesisAgent {
  private client: Anthropic;

  constructor(
    private config: SphinxConfig,
    private projectPath: string
  ) {
    this.client = new Anthropic({ apiKey: config.apiKey });
  }

  async execute(recon: ReconReport): Promise<HypothesisReport> {
    if (!this.config.apiKey) {
      return { type: "hypothesis", hypotheses: [] };
    }

    const tools = createAgentTools(this.projectPath);

    // Build a focused prompt based on recon results
    const entryPointsList = recon.entryPoints
      .slice(0, 20)
      .map((ep) => `  - ${ep.method || "HANDLER"} ${ep.path} (${ep.file}:${ep.line})`)
      .join("\n");

    const authInfo =
      recon.authBoundaries
        .map((ab) => `  - ${ab.file}:${ab.line} — ${ab.description}`)
        .join("\n") || "  No authentication boundaries detected";

    const prompt = `Perform hypothesis-driven security analysis on this codebase.

## Reconnaissance Results
Tech stack: ${recon.techStack.join(", ") || "unknown"}
Attack surface: ${recon.attackSurface}

Entry points:
${entryPointsList || "  None discovered"}

Authentication boundaries:
${authInfo}

## Instructions
1. Read the key entry point files using the tools
2. For each significant function, generate security hypotheses — what COULD go wrong?
3. Focus on: auth bypasses, race conditions, injection vectors, business logic flaws, crypto misuse
4. Think like an attacker — what assumptions does the code make that you could violate?
5. Prioritize hypotheses by severity and likelihood
6. Output your hypotheses as JSON`;

    const messages: Anthropic.MessageParam[] = [{ role: "user", content: prompt }];

    let turns = 0;
    while (turns < MAX_TURNS) {
      turns++;

      const response = await this.client.messages.create({
        model: this.config.model,
        max_tokens: 8192,
        system: HYPOTHESIS_SYSTEM,
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
        return this.parseHypotheses(text.text);
      }
      break;
    }

    return { type: "hypothesis", hypotheses: [] };
  }

  /**
   * Convert confirmed hypotheses into vulnerability findings.
   */
  hypothesesToVulnerabilities(hypotheses: SecurityHypothesis[]): Vulnerability[] {
    return hypotheses.map((h) => ({
      id: h.id,
      rule: `hypothesis:${h.category}`,
      title: `[Hypothesis] ${h.hypothesis.slice(0, 80)}`,
      description: `${h.hypothesis}\n\nReasoning: ${h.reasoning}\n\nInvestigation: ${h.investigationSteps.join("; ")}`,
      severity: h.estimatedSeverity,
      category: h.category,
      confidence: "medium" as const,
      location: {
        file: h.file,
        line: h.line,
        snippet: h.functionName,
      },
    }));
  }

  private parseHypotheses(text: string): HypothesisReport {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return { type: "hypothesis", hypotheses: [] };

    try {
      const data = JSON.parse(jsonMatch[0]);
      const hypotheses: SecurityHypothesis[] = (data.hypotheses || []).map((h: any, i: number) => ({
        id: `HYPO-${String(i + 1).padStart(3, "0")}`,
        functionName: h.functionName || "unknown",
        file: h.file || "",
        line: h.line || 0,
        hypothesis: h.hypothesis || "",
        category: h.category || "unknown",
        estimatedSeverity: (h.estimatedSeverity || "medium") as Severity,
        reasoning: h.reasoning || "",
        investigationSteps: h.investigationSteps || [],
      }));

      return { type: "hypothesis", hypotheses };
    } catch {
      return { type: "hypothesis", hypotheses: [] };
    }
  }
}
