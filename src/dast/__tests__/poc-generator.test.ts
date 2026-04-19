import { describe, it, expect } from "vitest";

import { parsePoc } from "../poc-generator.js";

// parsePoc handles 3 disjoint return shapes that the caller branches on:
// no-JSON sentinel, malformed-JSON sentinel, and successful parse with
// per-field defaults. All three are testable here without the live
// Anthropic call.

describe("parsePoc — no JSON in text", () => {
  it("returns a 'PoC generation failed' sentinel with the raw text as description", () => {
    const result = parsePoc("I can't generate a PoC for this finding.", "SPX-0001");
    expect(result).toMatchObject({
      vulnerabilityId: "SPX-0001",
      title: "PoC generation failed",
      expectedResult: "N/A",
      impact: "N/A",
      verified: false,
    });
    expect(result.description).toContain("I can't generate");
  });

  it("truncates the raw-text description at 200 chars to avoid giant fallback descriptions", () => {
    const longText = "A".repeat(500);
    const result = parsePoc(longText, "SPX-0001");
    expect(result.description).toHaveLength(200);
    expect(result.description).toBe("A".repeat(200));
  });
});

describe("parsePoc — malformed JSON", () => {
  it("returns a 'PoC parse failed' sentinel on JSON syntax error (braces match but contents invalid)", () => {
    // The JSON-extraction regex /\{[\s\S]*\}/ requires matching braces
    // to enter the try/catch branch. So to exercise "parse failed", we
    // need input with a balanced {...} whose contents fail JSON.parse
    // — unquoted keys are the minimal reproducer.
    const result = parsePoc('{title: "no quotes on key", description: "bad"}', "SPX-0042");
    expect(result.title).toBe("PoC parse failed");
    expect(result.vulnerabilityId).toBe("SPX-0042");
    expect(result.verified).toBe(false);
  });

  it("distinguishes 'parse failed' (malformed JSON) from 'generation failed' (no JSON)", () => {
    // Title text difference is the operator's signal for whether
    // the LLM produced no JSON at all vs produced broken JSON —
    // two different upstream issues that need different debugging.
    const noJson = parsePoc("refused to answer", "X").title;
    const brokenJson = parsePoc("{unquoted: key}", "X").title;
    expect(noJson).toBe("PoC generation failed");
    expect(brokenJson).toBe("PoC parse failed");
  });
});

describe("parsePoc — successful parse", () => {
  it("maps all fields from valid JSON to the ProofOfConcept shape", () => {
    const text = JSON.stringify({
      title: "SQLi via search param",
      description: "User-controlled search param concatenated into SQL query.",
      curlCommand: "curl 'http://host/search?q=%27%20OR%201%3D1--'",
      pythonScript: "import requests; requests.get(...)",
      httpRequest: "GET /search?q=%27+OR+1%3D1-- HTTP/1.1\\nHost: host",
      expectedResult: "Database error in response body.",
      impact: "Read arbitrary data from users table.",
    });
    const result = parsePoc(text, "SPX-0100");
    expect(result).toEqual({
      vulnerabilityId: "SPX-0100",
      title: "SQLi via search param",
      description: "User-controlled search param concatenated into SQL query.",
      curlCommand: "curl 'http://host/search?q=%27%20OR%201%3D1--'",
      pythonScript: "import requests; requests.get(...)",
      httpRequest: "GET /search?q=%27+OR+1%3D1-- HTTP/1.1\\nHost: host",
      expectedResult: "Database error in response body.",
      impact: "Read arbitrary data from users table.",
      verified: false,
    });
  });

  it("applies default title 'PoC for <vulnId>' when the model omits title", () => {
    const text = JSON.stringify({ description: "only desc" });
    expect(parsePoc(text, "SPX-0200").title).toBe("PoC for SPX-0200");
  });

  it("applies empty-string defaults for missing description/expectedResult/impact", () => {
    const text = JSON.stringify({ title: "T" });
    const result = parsePoc(text, "X");
    expect(result.description).toBe("");
    expect(result.expectedResult).toBe("");
    expect(result.impact).toBe("");
  });

  it("leaves optional curlCommand / pythonScript / httpRequest undefined when absent", () => {
    // These three are optional on ProofOfConcept — the AI emits whichever
    // formats make sense for the vuln. Pin that they stay undefined rather
    // than coerced to "" (empty-string would mean 'empty script' which is
    // different from 'no script').
    const result = parsePoc("{}", "X");
    expect(result.curlCommand).toBeUndefined();
    expect(result.pythonScript).toBeUndefined();
    expect(result.httpRequest).toBeUndefined();
  });

  it("sets verified=false on successful parse (verification happens separately in the fuzzer)", () => {
    // The verified flag only flips when live execution confirms exploitation.
    // parsePoc just builds the template; verification is the fuzzer's job.
    expect(parsePoc('{"title": "T"}', "X").verified).toBe(false);
  });
});
