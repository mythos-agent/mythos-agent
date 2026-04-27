import { describe, it, expect, vi } from "vitest";
import { wrapLLMClientWithLogging, type TurnRecord } from "../logging-client.js";
import type { LLMClient } from "../../../llm/index.js";

// A3b diagnostic-logging tests. The wrapper sits at the LLMClient
// boundary and is what lets the calibration harness answer "did the
// agent reach for find_ast_pattern at all?" — the central question
// when a 0-variants outcome could mean either "design failed" or
// "model never used the tool we seeded for it."

function buildResponse(
  overrides: Partial<{
    stop_reason: string;
    text: string;
    toolUses: Array<{ id: string; name: string; input: unknown }>;
    usage: { input_tokens: number; output_tokens: number; cache_read_input_tokens?: number };
  }> = {}
) {
  const content: Array<{ type: string; [k: string]: unknown }> = [];
  if (overrides.text !== undefined) {
    content.push({ type: "text", text: overrides.text });
  }
  for (const tu of overrides.toolUses ?? []) {
    content.push({ type: "tool_use", ...tu });
  }
  return {
    id: "msg_test",
    type: "message",
    role: "assistant",
    model: "test-model",
    stop_reason: overrides.stop_reason ?? "end_turn",
    stop_sequence: null,
    usage: overrides.usage ?? { input_tokens: 10, output_tokens: 5 },
    content,
  };
}

function buildClient(response: unknown): LLMClient {
  return {
    messages: { create: vi.fn().mockResolvedValue(response) },
  } as never;
}

describe("wrapLLMClientWithLogging — pass-through behavior", () => {
  it("forwards messages.create and returns the underlying response", async () => {
    const fakeResponse = buildResponse({ text: "hello" });
    const base = buildClient(fakeResponse);
    const wrapped = wrapLLMClientWithLogging(base, () => {});

    const result = await wrapped.messages.create({
      model: "x",
      max_tokens: 100,
      messages: [],
    } as never);

    expect(result).toBe(fakeResponse);
    expect(base.messages.create as ReturnType<typeof vi.fn>).toHaveBeenCalledOnce();
  });
});

describe("wrapLLMClientWithLogging — turn record shape", () => {
  it("captures tool calls so we can tell whether find_ast_pattern was used", async () => {
    // The whole reason this module exists: when the agent emits a
    // tool_use block, the record must surface name + input so a
    // post-run analysis can answer "did Sonnet reach for the seeded
    // AST tool, or did it stay on regex search_code?"
    const fakeResponse = buildResponse({
      stop_reason: "tool_use",
      text: "I'll look for the regex literal.",
      toolUses: [{ id: "tu_1", name: "find_ast_pattern", input: { kind: "regex" } }],
    });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    expect(records).toHaveLength(1);
    expect(records[0].turn).toBe(1);
    expect(records[0].stopReason).toBe("tool_use");
    expect(records[0].toolCalls).toEqual([{ name: "find_ast_pattern", input: { kind: "regex" } }]);
    expect(records[0].textPreview).toContain("regex literal");
    expect(records[0].usage.inputTokens).toBe(10);
    expect(records[0].usage.outputTokens).toBe(5);
    expect(records[0].timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(records[0].durationMs).toBeGreaterThanOrEqual(0);
  });

  it("records empty toolCalls and a non-null textPreview on a pure-text turn", async () => {
    const fakeResponse = buildResponse({
      stop_reason: "end_turn",
      text: '{"variants":[]}',
    });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    expect(records[0].toolCalls).toEqual([]);
    expect(records[0].textPreview).toBe('{"variants":[]}');
  });

  it("returns null textPreview when there is no text block", async () => {
    const fakeResponse = buildResponse({
      stop_reason: "tool_use",
      toolUses: [{ id: "tu_1", name: "search_code", input: { pattern: "x" } }],
    });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    expect(records[0].textPreview).toBeNull();
  });

  it("forwards cache_read_input_tokens when present", async () => {
    const fakeResponse = buildResponse({
      usage: { input_tokens: 5, output_tokens: 3, cache_read_input_tokens: 2000 },
    });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    expect(records[0].usage.cacheReadInputTokens).toBe(2000);
  });
});

describe("wrapLLMClientWithLogging — turn counter", () => {
  it("increments turn across multiple calls on the same wrapped client", async () => {
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(buildResponse({ text: "ok" })), (r) =>
      records.push(r)
    );

    await wrapped.messages.create({} as never);
    await wrapped.messages.create({} as never);
    await wrapped.messages.create({} as never);

    expect(records.map((r) => r.turn)).toEqual([1, 2, 3]);
  });
});

describe("wrapLLMClientWithLogging — truncation", () => {
  it("truncates long text previews on intermediate (tool-use) turns with a marker", async () => {
    // Intermediate turns keep the small cap so the JSONL log stays
    // compact across what may be 20+ tool-use turns. Exact cap
    // (TEXT_PREVIEW_CAP, currently 400) is intentionally not asserted
    // so the constant can be tuned without breaking this test.
    const longText = "x".repeat(500);
    const fakeResponse = buildResponse({ stop_reason: "tool_use", text: longText });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    expect(records[0].textPreview!.length).toBeLessThan(longText.length);
    expect(records[0].textPreview).toMatch(/…\[\+\d+\]$/);
  });

  it("captures the full final response on end_turn (the actual variants payload)", async () => {
    // The whole point of A3b diagnostic logging is to see the
    // variant-analyzer's final answer — capping it at the same 400
    // chars as intermediate turns was the bug that made post-fix
    // calibration runs impossible to diagnose. End-turn responses get
    // a much larger cap (currently 64KB), so a normal 4-8KB final
    // answer round-trips intact.
    const finalAnswer = '{"rootCauseAnalysis":"' + "x".repeat(4000) + '","variants":[]}';
    const fakeResponse = buildResponse({ stop_reason: "end_turn", text: finalAnswer });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    expect(records[0].textPreview).toBe(finalAnswer);
    expect(records[0].textPreview).not.toMatch(/…\[\+\d+\]$/);
  });

  it("still caps end_turn responses that exceed the final-text limit", async () => {
    // Even on end_turn, a runaway response must not blow up the log.
    // 256KB is well above the 64KB cap → must be truncated.
    const runawayText = "z".repeat(256 * 1024);
    const fakeResponse = buildResponse({ stop_reason: "end_turn", text: runawayText });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    expect(records[0].textPreview!.length).toBeLessThan(runawayText.length);
    expect(records[0].textPreview).toMatch(/…\[\+\d+\]$/);
  });

  it("marks oversized tool inputs as __truncated rather than dropping them", async () => {
    // Real agent tool calls (e.g. find_ast_pattern with a long source
    // code argument) can exceed the per-input cap. The record should
    // mark truncation explicitly so a downstream consumer can tell
    // "model emitted exactly this" from "we shortened this on the way
    // out."
    const bigString = "y".repeat(2000);
    const fakeResponse = buildResponse({
      stop_reason: "tool_use",
      toolUses: [{ id: "tu_1", name: "find_ast_pattern", input: { source: bigString } }],
    });
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(buildClient(fakeResponse), (r) => records.push(r));

    await wrapped.messages.create({} as never);

    const recordedInput = records[0].toolCalls[0].input as Record<string, unknown>;
    expect(recordedInput.__truncated).toBe(true);
    expect(typeof recordedInput.preview).toBe("string");
    expect(recordedInput.fullLength).toBeGreaterThan(2000);
  });
});

describe("wrapLLMClientWithLogging — error path", () => {
  it("records the error and re-throws so callers see the same failure", async () => {
    const failingClient: LLMClient = {
      messages: {
        create: vi.fn().mockRejectedValue(new Error("429 rate_limit_error")),
      },
    } as never;
    const records: TurnRecord[] = [];
    const wrapped = wrapLLMClientWithLogging(failingClient, (r) => records.push(r));

    await expect(wrapped.messages.create({} as never)).rejects.toThrow("429 rate_limit_error");
    expect(records).toHaveLength(1);
    expect(records[0].error).toContain("429");
    expect(records[0].stopReason).toBeNull();
    expect(records[0].toolCalls).toEqual([]);
  });
});
