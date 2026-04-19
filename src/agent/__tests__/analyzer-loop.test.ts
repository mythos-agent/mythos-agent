import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { AIAnalyzer } from "../analyzer.js";
import { DEFAULT_CONFIG, type MythosConfig, type Vulnerability } from "../../types/index.js";
import { createMockClient, type MockMessage } from "../../__tests__/llm-mock.js";

// These tests exercise the AIAnalyzer's 20-turn agentic loop end-to-end
// — the piece deliberately left untested in f8d08ef (which only covered
// the pure response parser). The LLM-mock harness now lives at
// src/__tests__/llm-mock.ts as a shared util; future Recon/Hypothesis/
// Exploit/SmartFuzzer/PoC loop tests import it from there.

const tmpDirs: string[] = [];
function fixture(files: Record<string, string> = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-analyzer-loop-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

function vuln(id: string, overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id,
    rule: `test:${id}`,
    title: `Original ${id}`,
    description: "d",
    severity: "medium",
    category: "test",
    confidence: "medium",
    location: { file: "a.ts", line: 1 },
    ...overrides,
  };
}

function cfgWithKey(): MythosConfig {
  const c = structuredClone(DEFAULT_CONFIG);
  c.apiKey = "test-key-not-sent-to-network";
  return c;
}

describe("AIAnalyzer loop — immediate final answer (no tool use)", () => {
  it("returns parsed result after a single create() call when stop_reason=end_turn", async () => {
    const dir = fixture();
    const phase1 = [vuln("SPX-0001")];
    const { client, calls } = createMockClient([
      {
        stop_reason: "end_turn",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              verified: [{ originalId: "SPX-0001", isReal: true, reasoning: "LGTM" }],
              discovered: [],
            }),
          },
        ],
      },
    ]);

    const analyzer = new AIAnalyzer(cfgWithKey(), client);
    const result = await analyzer.analyze(dir, phase1);

    expect(calls).toHaveLength(1);
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0]).toMatchObject({
      id: "SPX-0001",
      aiVerified: true,
      confidence: "high",
    });
    expect(result.dismissedCount).toBe(0);
  });

  it("sends temperature=0 on every call (regression guard for e6d1231)", async () => {
    // The pre-e6d1231 state defaulted temperature=1, producing
    // non-deterministic findings and breaking diff-mode /
    // model-drift regression detection. Pin temperature=0 here so
    // any future refactor that drops it fails this test.
    const dir = fixture();
    const { client, calls } = createMockClient([
      { stop_reason: "end_turn", content: [{ type: "text", text: "{}" }] },
    ]);
    await new AIAnalyzer(cfgWithKey(), client).analyze(dir, []);
    expect(calls[0].temperature).toBe(0);
  });
});

describe("AIAnalyzer loop — tool-use round-trip", () => {
  it("executes a tool call and feeds the result back as a user-role tool_result block", async () => {
    // Fixture: a file list_files can enumerate. Uses the real
    // executeToolCall so the loop's tool_result content has the
    // scanner's actual output format — tests the integration, not
    // a stubbed shape.
    const dir = fixture({ "a.ts": "export const x = 1;\n", "b.ts": "export const y = 2;\n" });
    const { client, calls } = createMockClient([
      // Turn 1: model asks to list the project
      {
        stop_reason: "tool_use",
        content: [{ type: "tool_use", id: "toolu_1", name: "list_files", input: { path: "." } }],
      },
      // Turn 2: model produces its final answer
      {
        stop_reason: "end_turn",
        content: [
          {
            type: "text",
            text: JSON.stringify({ verified: [], discovered: [] }),
          },
        ],
      },
    ]);

    await new AIAnalyzer(cfgWithKey(), client).analyze(dir, []);

    expect(calls).toHaveLength(2);
    // The second call's messages must now include the tool_use
    // response (as assistant content) AND a tool_result block
    // (as user content) — that round-trip is the core invariant.
    const secondMessages = calls[1].messages as Array<{
      role: string;
      content: unknown;
    }>;
    expect(secondMessages.length).toBeGreaterThanOrEqual(3);
    // Role sequence: user (original prompt) → assistant (tool_use)
    // → user (tool_result).
    expect(secondMessages[secondMessages.length - 2].role).toBe("assistant");
    expect(secondMessages[secondMessages.length - 1].role).toBe("user");
    const lastContent = secondMessages[secondMessages.length - 1].content as Array<{
      type: string;
      tool_use_id?: string;
    }>;
    expect(lastContent[0].type).toBe("tool_result");
    expect(lastContent[0].tool_use_id).toBe("toolu_1");
  });

  it("executes every tool_use block in a single response when the model batches tool calls", async () => {
    // Claude sometimes emits multiple tool_use blocks in one
    // assistant turn. Each one must be individually executed and
    // its tool_result paired back by id. Two list_files calls in
    // one turn must produce two tool_result blocks in the next
    // user turn.
    const dir = fixture({ "a.ts": "a", "sub/b.ts": "b" });
    const { client, calls } = createMockClient([
      {
        stop_reason: "tool_use",
        content: [
          { type: "tool_use", id: "toolu_A", name: "list_files", input: { path: "." } },
          { type: "tool_use", id: "toolu_B", name: "list_files", input: { path: "sub" } },
        ],
      },
      {
        stop_reason: "end_turn",
        content: [{ type: "text", text: JSON.stringify({ verified: [], discovered: [] }) }],
      },
    ]);

    await new AIAnalyzer(cfgWithKey(), client).analyze(dir, []);

    const secondMessages = calls[1].messages as Array<{ role: string; content: unknown }>;
    const lastContent = secondMessages[secondMessages.length - 1].content as Array<{
      type: string;
      tool_use_id?: string;
    }>;
    expect(lastContent).toHaveLength(2);
    expect(lastContent.map((b) => b.tool_use_id).sort()).toEqual(["toolu_A", "toolu_B"]);
  });
});

describe("AIAnalyzer loop — exhaustion + degenerate-response fallbacks", () => {
  it("returns phase1 findings unchanged when the loop exhausts MAX_TURNS (20)", async () => {
    // Construct 20 identical tool_use responses so the loop never
    // produces a final answer. After turn 20 the while condition
    // fails; control falls through to the fallback return.
    const dir = fixture({ "a.ts": "x" });
    const MAX_TURNS = 20;
    const responses: MockMessage[] = [];
    for (let i = 0; i < MAX_TURNS + 5; i++) {
      responses.push({
        stop_reason: "tool_use",
        content: [
          {
            type: "tool_use",
            id: `toolu_${i}`,
            name: "list_files",
            input: { path: "." },
          },
        ],
      });
    }
    const phase1 = [vuln("SPX-0001"), vuln("SPX-0002")];
    const { client, calls } = createMockClient(responses);

    const result = await new AIAnalyzer(cfgWithKey(), client).analyze(dir, phase1);

    // Exactly MAX_TURNS calls, no more.
    expect(calls).toHaveLength(MAX_TURNS);
    // Fallback preserves phase1 verbatim — aiVerified NOT set.
    expect(result.confirmed).toEqual(phase1);
    expect(result.discovered).toEqual([]);
    expect(result.dismissedCount).toBe(0);
  });

  it("falls back to phase1 when the final response has no text block (empty content)", async () => {
    // Edge case: model replies with stop_reason=end_turn but no
    // text — caught by the `if (textBlock && textBlock.type === "text")`
    // guard, which breaks out of the loop and hits the fallback.
    const dir = fixture();
    const phase1 = [vuln("SPX-0001")];
    const { client } = createMockClient([{ stop_reason: "end_turn", content: [] }]);
    const result = await new AIAnalyzer(cfgWithKey(), client).analyze(dir, phase1);
    expect(result.confirmed).toEqual(phase1);
    expect(result.dismissedCount).toBe(0);
  });

  it("parses discovered findings from the final response and assigns SPX-NNNN ids past phase1", async () => {
    // End-to-end: the loop returns final JSON including a
    // discovered[] entry, parseAnalysisResponse processes it,
    // and the returned result has the discovered finding with
    // the correct id allocation.
    const dir = fixture();
    const phase1 = [vuln("SPX-0001"), vuln("SPX-0002")];
    const { client } = createMockClient([
      {
        stop_reason: "end_turn",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              verified: [],
              discovered: [
                {
                  title: "AI-spotted XXE",
                  description: "d",
                  severity: "high",
                  category: "injection",
                  cwe: "CWE-611",
                  file: "parser.ts",
                  line: 42,
                },
              ],
            }),
          },
        ],
      },
    ]);

    const result = await new AIAnalyzer(cfgWithKey(), client).analyze(dir, phase1);

    expect(result.discovered).toHaveLength(1);
    expect(result.discovered[0]).toMatchObject({
      id: "SPX-0003", // phase1.length + 1
      title: "AI-spotted XXE",
      aiVerified: true,
    });
  });

  it("dismisses findings the model flags isReal=false and exposes the count", async () => {
    const dir = fixture();
    const phase1 = [
      vuln("SPX-0001", { title: "Real bug" }),
      vuln("SPX-0002", { title: "False positive" }),
    ];
    const { client } = createMockClient([
      {
        stop_reason: "end_turn",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              verified: [
                { originalId: "SPX-0001", isReal: true, reasoning: "R" },
                { originalId: "SPX-0002", isReal: false, reasoning: "safe" },
              ],
              discovered: [],
            }),
          },
        ],
      },
    ]);

    const result = await new AIAnalyzer(cfgWithKey(), client).analyze(dir, phase1);

    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].id).toBe("SPX-0001");
    expect(result.dismissedCount).toBe(1);
  });
});
