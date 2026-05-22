import { describe, it, expect, vi } from "vitest";
import { triage } from "../triage.js";
import type { DivergenceClass } from "../types.js";
import type { LLMClient } from "../../../llm/index.js";

const CLASS: DivergenceClass = {
  signature: "field:hostname:native-url|url-parse:a.a|A.a",
  kind: "field",
  field: "hostname",
  parserA: "native-url",
  parserB: "url-parse",
  representativeInput: "http://good.com@evil.com/",
  count: 3,
};

function mockClient(text: string): LLMClient {
  return {
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [{ type: "text", text }],
        stop_reason: "end_turn",
      }),
    },
  } as unknown as LLMClient;
}

describe("triage", () => {
  it("attaches the LLM category and rationale to each class", async () => {
    const client = mockClient(
      '{"category":"likely-exploitable","rationale":"hostname disagreement enables SSRF bypass"}'
    );
    const out = await triage([CLASS], client, "claude-sonnet-4-6");
    expect(out[0].category).toBe("likely-exploitable");
    expect(out[0].rationale).toContain("SSRF");
  });

  it("returns the class un-triaged (no category) when the LLM call throws", async () => {
    const client = {
      messages: { create: vi.fn().mockRejectedValue(new Error("network")) },
    } as unknown as LLMClient;
    const out = await triage([CLASS], client, "claude-sonnet-4-6");
    expect(out[0].category).toBeUndefined();
    expect(out[0].signature).toBe(CLASS.signature);
  });

  it("returns the class un-triaged when the LLM returns unparseable output", async () => {
    const out = await triage([CLASS], mockClient("no json here"), "claude-sonnet-4-6");
    expect(out[0].category).toBeUndefined();
  });
});
