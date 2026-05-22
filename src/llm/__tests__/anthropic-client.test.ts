import { describe, it, expect } from "vitest";
import type Anthropic from "@anthropic-ai/sdk";
import { withPromptCache } from "../anthropic-client.js";

describe("withPromptCache", () => {
  it("converts a string system prompt into a cached text block", () => {
    const out = withPromptCache({
      model: "claude-sonnet-4-6",
      max_tokens: 100,
      system: "You are a helper.",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(out.system).toEqual([
      { type: "text", text: "You are a helper.", cache_control: { type: "ephemeral" } },
    ]);
  });

  it("marks the last tool with cache_control and leaves earlier tools alone", () => {
    const out = withPromptCache({
      model: "claude-sonnet-4-6",
      max_tokens: 100,
      messages: [{ role: "user", content: "hi" }],
      tools: [
        { name: "a", description: "", input_schema: { type: "object", properties: {} } },
        { name: "b", description: "", input_schema: { type: "object", properties: {} } },
      ],
    });
    const tools = out.tools as Array<Anthropic.Tool & { cache_control?: unknown }>;
    expect(tools[1].cache_control).toEqual({ type: "ephemeral" });
    expect(tools[0].cache_control).toBeUndefined();
  });

  it("marks the last block of a block-array system prompt", () => {
    const out = withPromptCache({
      model: "claude-sonnet-4-6",
      max_tokens: 100,
      system: [
        { type: "text", text: "block one" },
        { type: "text", text: "block two" },
      ],
      messages: [{ role: "user", content: "hi" }],
    });
    expect((out.system as any)[1].cache_control).toEqual({ type: "ephemeral" });
    expect((out.system as any)[0].cache_control).toBeUndefined();
  });

  it("leaves the messages transcript untouched", () => {
    const messages = [{ role: "user" as const, content: "hi" }];
    const out = withPromptCache({ model: "claude-sonnet-4-6", max_tokens: 100, messages });
    expect(out.messages).toEqual(messages);
  });

  it("handles an absent system and absent tools without throwing", () => {
    const out = withPromptCache({
      model: "claude-sonnet-4-6",
      max_tokens: 100,
      messages: [{ role: "user", content: "hi" }],
    });
    expect(out.system).toBeUndefined();
    expect(out.tools).toBeUndefined();
  });
});
