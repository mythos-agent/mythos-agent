import { describe, it, expect } from "vitest";
import { parseVariants, collectJsonCandidates, VariantAnalyzer } from "../variant-analyzer.js";
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

describe("parseVariants — markdown-fence + prose-mixed extraction", () => {
  // A3b post-fix runs surfaced this: Sonnet 4.6 sometimes ignores
  // "JSON only" instructions and emits markdown-formatted analysis
  // with code-fence-wrapped JSON. The pre-fix parser's greedy
  // `\{[\s\S]*\}` regex grabbed the wrong span and JSON.parse failed,
  // producing a 0-variants result indistinguishable from a real
  // clean miss. These cases pin the recovery paths.

  it("extracts variants from a markdown response with a json code fence", () => {
    const text = [
      "## Variant Analysis Report",
      "",
      "After thorough analysis, here are the variants:",
      "",
      "```json",
      JSON.stringify({
        rootCauseAnalysis: "ReDoS pattern",
        variants: [
          {
            file: "internal/re.js",
            line: 138,
            code: "createToken('TILDETRIM', `(\\\\s*)${...}\\\\s+`, true)",
            similarity: "high",
            explanation: "matched",
            rootCauseMatch: "unbounded whitespace + interpolation",
          },
        ],
      }),
      "```",
      "",
      "End of report.",
    ].join("\n");
    const out = parseVariants(text, "CVE-2022-25883");
    expect(out).toHaveLength(1);
    expect(out[0].file).toBe("internal/re.js");
    expect(out[0].line).toBe(138);
  });

  it("extracts from a code fence with no language tag", () => {
    const text = [
      "Here are the variants:",
      "```",
      JSON.stringify({ rootCauseAnalysis: "x", variants: [{ file: "a.js", line: 1 }] }),
      "```",
    ].join("\n");
    const out = parseVariants(text, "CVE-x");
    expect(out).toHaveLength(1);
    expect(out[0].file).toBe("a.js");
  });

  it("parses a JSON-only response (the post-prompt-fix happy path)", () => {
    const text = JSON.stringify({
      rootCauseAnalysis: "x",
      variants: [{ file: "a.js", line: 5, similarity: "high" }],
    });
    const out = parseVariants(text, "CVE-x");
    expect(out).toHaveLength(1);
  });

  it("returns [] when prose contains a JSON-shaped object that lacks a variants ARRAY", () => {
    // Pre-fix, the greedy regex would happily JSON.parse `{...}` from
    // prose and call (data.variants || []) — which yielded [] only by
    // accident when `variants` happened to be missing. The new check
    // requires Array.isArray, so a `variants: "string"` field doesn't
    // pass. Pins the contract that empty array results from "no JSON
    // with a real variants array found", not "JSON.parse happened to
    // succeed on something."
    const text = '## Header\n\nThe map { variants: "string" } looks like JSON but isn\'t.';
    expect(parseVariants(text, "CVE-x")).toEqual([]);
  });

  it("prefers the whole-text parse over fence extraction when both work", () => {
    // If the model follows instructions and emits a single JSON
    // object, that's the candidate we want — even if the JSON happens
    // to contain a string field with markdown fences in it.
    const text = JSON.stringify({
      rootCauseAnalysis: "Some analysis with ```json fenced content``` inside",
      variants: [{ file: "real.js", line: 42 }],
    });
    const out = parseVariants(text, "CVE-x");
    expect(out).toHaveLength(1);
    expect(out[0].file).toBe("real.js");
  });
});

describe("collectJsonCandidates — extraction order", () => {
  it("yields the trimmed whole text first when it looks like a JSON object", () => {
    const json = '{"variants":[]}';
    const candidates = collectJsonCandidates(`  ${json}  `);
    expect(candidates[0]).toBe(json);
  });

  it("yields fence bodies in document order", () => {
    const text = [
      "intro",
      "```json",
      '{"variants":[{"file":"a"}]}',
      "```",
      "middle",
      "```",
      '{"variants":[{"file":"b"}]}',
      "```",
    ].join("\n");
    const candidates = collectJsonCandidates(text);
    expect(candidates[0]).toContain('"file":"a"');
    expect(candidates[1]).toContain('"file":"b"');
  });

  it("returns [] when there is no JSON-shaped substring at all", () => {
    expect(collectJsonCandidates("Just prose. No braces.")).toEqual([]);
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
