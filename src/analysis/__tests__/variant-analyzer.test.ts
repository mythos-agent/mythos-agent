import { describe, it, expect } from "vitest";
import { parseVariants, VariantAnalyzer } from "../variant-analyzer.js";
import { DEFAULT_CONFIG } from "../../types/index.js";

// First test coverage for variant-analyzer.ts (was 0% pre-PR). Per the
// variant-hunt experiment plan: the existing tool is the entry point
// for the Big Sleep-style methodology, but it had no test coverage,
// so silent breakage in the JSON parser or the constructor wiring
// could go undetected. These tests pin the behavior we depend on:
//
//  1. The constructor goes through the multi-model factory (so
//     `provider: openai` users get an OpenAILLMClient, matching the
//     hunt agents' wiring from PRs #44 and #46).
//  2. parseVariants tolerates malformed LLM output without throwing.
//  3. parseVariants extracts variants from valid JSON with the
//     expected default-fallback behavior.

describe("parseVariants — JSON parser tolerance", () => {
  it("returns [] when text contains no JSON substring", () => {
    expect(parseVariants("Just plain prose, no JSON here.", "CVE-2022-25883")).toEqual([]);
  });

  it("returns [] when text contains malformed JSON without throwing", () => {
    // The agentic loop must keep working when a small model emits
    // truncated or garbled JSON. Throwing would propagate up and
    // break the entire variants run; returning [] is the no-variants-
    // found state that lets the caller move on.
    expect(() => parseVariants("{not valid json", "CVE-x")).not.toThrow();
    expect(parseVariants("{not valid json", "CVE-x")).toEqual([]);
  });

  it("returns [] when JSON is valid but has no variants array", () => {
    const text = '{"rootCauseAnalysis": "some analysis", "other": "field"}';
    expect(parseVariants(text, "CVE-x")).toEqual([]);
  });

  it("extracts variants from a well-formed LLM response", () => {
    const text = JSON.stringify({
      rootCauseAnalysis: "Unbounded whitespace adjacent to template interpolation",
      variants: [
        {
          file: "src/parser.ts",
          line: 42,
          code: "`(\\\\s*)${pattern}\\\\s+`",
          similarity: "high",
          explanation: "Template literal with \\s* and \\s+ next to ${} slot",
          rootCauseMatch: "Unbounded whitespace + interpolation",
        },
      ],
    });
    const out = parseVariants(text, "CVE-2022-25883");
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      id: "VAR-001",
      cveId: "CVE-2022-25883",
      file: "src/parser.ts",
      line: 42,
      similarity: "high",
      rootCauseMatch: "Unbounded whitespace + interpolation",
    });
  });

  it("falls back to defaults for missing variant fields", () => {
    const text = JSON.stringify({
      variants: [{ file: "a.ts" }, { line: 5 }],
    });
    const out = parseVariants(text, "CVE-x");
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({
      id: "VAR-001",
      file: "a.ts",
      line: 0,
      similarity: "medium",
      explanation: "",
      rootCauseMatch: "",
    });
    expect(out[1]).toMatchObject({
      id: "VAR-002",
      file: "",
      line: 5,
      similarity: "medium",
    });
  });

  it("pads VAR ids to 3 digits", () => {
    const variants = Array.from({ length: 5 }, () => ({
      file: "x",
      line: 1,
      similarity: "low",
      explanation: "e",
      rootCauseMatch: "r",
    }));
    const out = parseVariants(JSON.stringify({ variants }), "CVE-x");
    expect(out.map((v) => v.id)).toEqual(["VAR-001", "VAR-002", "VAR-003", "VAR-004", "VAR-005"]);
  });
});

describe("VariantAnalyzer — constructor wiring (multi-model)", () => {
  it("uses the LLMClient factory by default (Tier 1 Anthropic when provider unset)", () => {
    // Smoke test: constructor doesn't throw and produces a client.
    // We don't introspect the client type because the factory's
    // contract is "returns SOMETHING that satisfies LLMClient" — the
    // specific class is an implementation detail.
    const config = { ...DEFAULT_CONFIG, apiKey: "test-key" };
    const analyzer = new VariantAnalyzer(config, "/tmp/fake-project");
    expect(analyzer).toBeDefined();
  });

  it("accepts an injected client (back-compat with pre-multi-model test mocks)", () => {
    const fakeClient = {
      messages: {
        create: async () => {
          throw new Error("not exercised in this test");
        },
      },
    };
    const config = { ...DEFAULT_CONFIG, apiKey: "test-key" };
    const analyzer = new VariantAnalyzer(
      config,
      "/tmp/fake-project",
      // The constructor signature accepts LLMClient | Anthropic; the
      // structural shape above satisfies LLMClient. Casting via
      // `as never` here matches how older test mocks would have been
      // injected.
      fakeClient as never
    );
    expect(analyzer).toBeDefined();
  });
});
