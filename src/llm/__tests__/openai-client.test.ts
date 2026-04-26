import { describe, it, expect } from "vitest";
import type Anthropic from "@anthropic-ai/sdk";
import type OpenAI from "openai";
import {
  translateRequest,
  translateMessages,
  translateTools,
  translateResponse,
  translateStopReason,
} from "../openai-client.js";

// These tests pin the five translation points enumerated in
// docs/multi-model.md and issue #43. They exercise the conversion in
// both directions (Anthropic-shaped request → OpenAI request, OpenAI
// response → Anthropic-shaped Message) without instantiating a live
// OpenAI client. Live-provider verification is the maintainer's
// responsibility per the tier-system policy — see
// docs/multi-model.md § Stage 2 verification.

describe("translateStopReason", () => {
  it("maps OpenAI tool_calls → Anthropic tool_use (the agentic-loop driver)", () => {
    expect(translateStopReason("tool_calls")).toBe("tool_use");
  });

  it("maps OpenAI legacy function_call → Anthropic tool_use", () => {
    expect(translateStopReason("function_call")).toBe("tool_use");
  });

  it("maps OpenAI stop → Anthropic end_turn", () => {
    expect(translateStopReason("stop")).toBe("end_turn");
  });

  it("maps OpenAI length → Anthropic max_tokens", () => {
    expect(translateStopReason("length")).toBe("max_tokens");
  });

  it("maps OpenAI content_filter → Anthropic refusal", () => {
    expect(translateStopReason("content_filter")).toBe("refusal");
  });

  it("falls back to end_turn for unknown reasons (defensive default)", () => {
    expect(translateStopReason(null as unknown as "stop")).toBe("end_turn");
  });
});

describe("translateTools — Anthropic tool def → OpenAI function tool", () => {
  it("renames input_schema → parameters and wraps in {type: function, function: {...}}", () => {
    const tools: Anthropic.Tool[] = [
      {
        name: "read_file",
        description: "Read a file",
        input_schema: {
          type: "object",
          properties: { path: { type: "string" } },
          required: ["path"],
        },
      },
    ];
    const out = translateTools(tools);
    expect(out).toEqual([
      {
        type: "function",
        function: {
          name: "read_file",
          description: "Read a file",
          parameters: {
            type: "object",
            properties: { path: { type: "string" } },
            required: ["path"],
          },
        },
      },
    ]);
  });

  it("returns empty array when no tools given", () => {
    expect(translateTools(undefined)).toEqual([]);
    expect(translateTools([])).toEqual([]);
  });

  it("falls back to empty description when Anthropic def omits it", () => {
    const tools: Anthropic.Tool[] = [
      {
        name: "list_files",
        // description intentionally omitted — some agent code emits this
        input_schema: { type: "object", properties: {} },
      },
    ];
    expect(translateTools(tools)[0].function.description).toBe("");
  });
});

describe("translateMessages — system message handling (translation point 1)", () => {
  it("string system → prepended {role: system, content: string}", () => {
    const out = translateMessages("You are a helper.", []);
    expect(out).toEqual([{ role: "system", content: "You are a helper." }]);
  });

  it("content-block array system → concatenates text blocks with newlines", () => {
    const out = translateMessages(
      [
        { type: "text", text: "Part 1" },
        { type: "text", text: "Part 2" },
      ],
      []
    );
    expect(out).toEqual([{ role: "system", content: "Part 1\nPart 2" }]);
  });

  it("undefined system → no system message in output", () => {
    const out = translateMessages(undefined, [{ role: "user", content: "hi" }]);
    expect(out).toEqual([{ role: "user", content: "hi" }]);
  });

  it("empty string system → no system message in output", () => {
    const out = translateMessages("", [{ role: "user", content: "hi" }]);
    expect(out).toEqual([{ role: "user", content: "hi" }]);
  });
});

describe("translateMessages — tool result threading (translation point 4)", () => {
  it("user message with tool_result blocks → separate role:tool messages", () => {
    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: "toolu_abc",
            content: "file contents here",
          },
        ],
      },
    ];
    const out = translateMessages(undefined, messages);
    expect(out).toEqual([
      {
        role: "tool",
        tool_call_id: "toolu_abc",
        content: "file contents here",
      },
    ]);
  });

  it("tool_result with content-block array → concatenated text", () => {
    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: "toolu_xyz",
            content: [
              { type: "text", text: "line 1" },
              { type: "text", text: "line 2" },
            ],
          },
        ],
      },
    ];
    const out = translateMessages(undefined, messages);
    expect(out[0]).toEqual({
      role: "tool",
      tool_call_id: "toolu_xyz",
      content: "line 1\nline 2",
    });
  });

  it("user message with text + tool_result → user text msg followed by tool msg (correct OpenAI threading order)", () => {
    const messages: Anthropic.MessageParam[] = [
      {
        role: "user",
        content: [
          { type: "text", text: "follow-up question" },
          {
            type: "tool_result",
            tool_use_id: "toolu_1",
            content: "result",
          },
        ],
      },
    ];
    const out = translateMessages(undefined, messages);
    expect(out).toEqual([
      { role: "user", content: "follow-up question" },
      { role: "tool", tool_call_id: "toolu_1", content: "result" },
    ]);
  });
});

describe("translateMessages — assistant tool_use blocks (translation point 2 + 4)", () => {
  it("assistant message with text + tool_use → message with content + tool_calls", () => {
    const messages: Anthropic.MessageParam[] = [
      {
        role: "assistant",
        content: [
          { type: "text", text: "Let me check that file." },
          {
            type: "tool_use",
            id: "toolu_call_1",
            name: "read_file",
            input: { path: "src/index.ts" },
          },
        ],
      },
    ];
    const out = translateMessages(undefined, messages);
    expect(out).toEqual([
      {
        role: "assistant",
        content: "Let me check that file.",
        tool_calls: [
          {
            id: "toolu_call_1",
            type: "function",
            function: {
              name: "read_file",
              arguments: JSON.stringify({ path: "src/index.ts" }),
            },
          },
        ],
      },
    ]);
  });

  it("assistant message with only tool_use → content: null + tool_calls (OpenAI requires explicit null)", () => {
    const messages: Anthropic.MessageParam[] = [
      {
        role: "assistant",
        content: [
          {
            type: "tool_use",
            id: "toolu_call_2",
            name: "list_files",
            input: {},
          },
        ],
      },
    ];
    const out = translateMessages(undefined, messages);
    expect(out[0]).toMatchObject({ role: "assistant", content: null });
    expect((out[0] as { tool_calls: unknown[] }).tool_calls).toHaveLength(1);
  });
});

describe("translateRequest — top-level field mapping", () => {
  it("passes through model, max_tokens, temperature, top_p, stop_sequences", () => {
    const out = translateRequest({
      model: "qwen-plus",
      max_tokens: 4096,
      temperature: 0.5,
      top_p: 0.9,
      stop_sequences: ["END"],
      messages: [{ role: "user", content: "hi" }],
    });
    expect(out.model).toBe("qwen-plus");
    expect(out.max_tokens).toBe(4096);
    expect(out.temperature).toBe(0.5);
    expect(out.top_p).toBe(0.9);
    expect(out.stop).toEqual(["END"]);
    expect(out.stream).toBe(false);
  });

  it("omits optional fields when not provided", () => {
    const out = translateRequest({
      model: "qwen-plus",
      max_tokens: 100,
      messages: [{ role: "user", content: "hi" }],
    });
    expect("temperature" in out).toBe(false);
    expect("top_p" in out).toBe(false);
    expect("stop" in out).toBe(false);
    expect("tools" in out).toBe(false);
  });
});

describe("translateResponse — OpenAI ChatCompletion → Anthropic Message", () => {
  function makeChoice(
    finishReason: OpenAI.Chat.ChatCompletion.Choice["finish_reason"],
    message: OpenAI.Chat.ChatCompletion.Choice["message"]
  ): OpenAI.Chat.ChatCompletion {
    return {
      id: "chatcmpl-test",
      object: "chat.completion",
      created: 1700000000,
      model: "qwen-plus",
      choices: [{ index: 0, finish_reason: finishReason, message, logprobs: null }],
      usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 },
    } as OpenAI.Chat.ChatCompletion;
  }

  it("plain text response → single text content block + end_turn", () => {
    const out = translateResponse(
      makeChoice("stop", {
        role: "assistant",
        content: "Here is the analysis.",
        refusal: null,
      } as OpenAI.Chat.ChatCompletion.Choice["message"]),
      "qwen-plus"
    );
    expect(out.stop_reason).toBe("end_turn");
    expect(out.content).toEqual([{ type: "text", text: "Here is the analysis.", citations: null }]);
    expect(out.role).toBe("assistant");
    expect(out.model).toBe("qwen-plus");
  });

  it("tool_calls response → tool_use content blocks + tool_use stop reason", () => {
    const out = translateResponse(
      makeChoice("tool_calls", {
        role: "assistant",
        content: null,
        refusal: null,
        tool_calls: [
          {
            id: "call_abc",
            type: "function",
            function: {
              name: "read_file",
              arguments: JSON.stringify({ path: "src/index.ts" }),
            },
          },
        ],
      } as OpenAI.Chat.ChatCompletion.Choice["message"]),
      "qwen-plus"
    );
    expect(out.stop_reason).toBe("tool_use");
    expect(out.content).toEqual([
      {
        type: "tool_use",
        id: "call_abc",
        name: "read_file",
        input: { path: "src/index.ts" },
      },
    ]);
  });

  it("text + tool_calls response → both block types in content (text first)", () => {
    const out = translateResponse(
      makeChoice("tool_calls", {
        role: "assistant",
        content: "I'll need to read this file.",
        refusal: null,
        tool_calls: [
          {
            id: "call_1",
            type: "function",
            function: { name: "read_file", arguments: '{"path":"a.ts"}' },
          },
        ],
      } as OpenAI.Chat.ChatCompletion.Choice["message"]),
      "qwen-plus"
    );
    expect(out.content).toHaveLength(2);
    expect(out.content[0].type).toBe("text");
    expect(out.content[1].type).toBe("tool_use");
  });

  it("malformed JSON in tool arguments → preserved as _raw_arguments rather than throwing", () => {
    // Smaller local models occasionally emit malformed JSON. Throwing
    // would break the agentic loop hard; preserving the raw lets the
    // agent (or a future repair pass) decide how to recover.
    const out = translateResponse(
      makeChoice("tool_calls", {
        role: "assistant",
        content: null,
        refusal: null,
        tool_calls: [
          {
            id: "call_bad",
            type: "function",
            function: { name: "read_file", arguments: "not valid json" },
          },
        ],
      } as OpenAI.Chat.ChatCompletion.Choice["message"]),
      "qwen-plus"
    );
    expect((out.content[0] as Anthropic.ToolUseBlock).input).toEqual({
      _raw_arguments: "not valid json",
    });
  });

  it("usage tokens map prompt_tokens → input_tokens, completion_tokens → output_tokens", () => {
    const out = translateResponse(
      makeChoice("stop", {
        role: "assistant",
        content: "ok",
        refusal: null,
      } as OpenAI.Chat.ChatCompletion.Choice["message"]),
      "qwen-plus"
    );
    expect(out.usage.input_tokens).toBe(10);
    expect(out.usage.output_tokens).toBe(20);
  });
});
