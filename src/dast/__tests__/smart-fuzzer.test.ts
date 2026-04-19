import { describe, it, expect } from "vitest";

import { isVulnerable, parsePayloads } from "../smart-fuzzer.js";

// smart-fuzzer.ts's class wraps a 20-turn Anthropic loop; tests there would
// need a mock client. But the detection oracle (`isVulnerable`) and payload
// parser (`parsePayloads`) are pure functions now exported for unit testing.
// They're where the subtle bugs live — detection branch ordering, invalid-
// regex fallback, JSON parse failure modes.

type Result = { status: number; time: number; body: string };
type Payload = { expectedIndicator: string; value: string };

function result(overrides: Partial<Result> = {}): Result {
  return { status: 200, time: 100, body: "", ...overrides };
}

function payload(overrides: Partial<Payload> = {}): Payload {
  return { expectedIndicator: "", value: "probe", ...overrides };
}

describe("isVulnerable — branch 1: 500 + DB error signature", () => {
  it("flags when status=500 and body contains 'sql'", () => {
    expect(
      isVulnerable(result({ status: 500, body: "SQL syntax error at line 1" }), payload())
    ).toBe(true);
  });

  it("flags 500 responses with 'exception' in body", () => {
    expect(
      isVulnerable(result({ status: 500, body: "Unhandled exception in handler" }), payload())
    ).toBe(true);
  });

  it("does NOT flag 500 with a generic error body lacking DB/exception keywords", () => {
    expect(isVulnerable(result({ status: 500, body: "oops" }), payload())).toBe(false);
  });
});

describe("isVulnerable — branch 2: reflected XSS", () => {
  it("flags when body contains the payload AND payload is XSS-shaped", () => {
    const xssValue = "<script>alert(1)</script>";
    expect(
      isVulnerable(
        result({ status: 200, body: `<div>reflected: ${xssValue}</div>` }),
        payload({ value: xssValue })
      )
    ).toBe(true);
  });

  it("does NOT flag a reflected value that isn't XSS-shaped (harmless reflection)", () => {
    // Echoing user input is fine if that input isn't a script/handler.
    // This branch specifically looks for <script/onload/onerror/onclick
    // in the PAYLOAD (not the body).
    expect(isVulnerable(result({ body: "you sent: hello" }), payload({ value: "hello" }))).toBe(
      false
    );
  });

  it("does NOT flag an XSS-shaped payload that wasn't reflected", () => {
    expect(
      isVulnerable(
        result({ body: "encoded: &lt;script&gt;alert(1)&lt;/script&gt;" }),
        payload({ value: "<script>alert(1)</script>" })
      )
    ).toBe(false);
  });
});

describe("isVulnerable — branch 3: time-based blind", () => {
  it("flags when WAITFOR payload takes >4500ms", () => {
    expect(
      isVulnerable(result({ time: 5200 }), payload({ value: "'; WAITFOR DELAY '0:0:5'--" }))
    ).toBe(true);
  });

  it("does NOT flag WAITFOR under 4500ms threshold", () => {
    expect(
      isVulnerable(result({ time: 4200 }), payload({ value: "'; WAITFOR DELAY '0:0:5'--" }))
    ).toBe(false);
  });

  it("does NOT flag slow response without WAITFOR in payload (not this signal)", () => {
    expect(isVulnerable(result({ time: 5500 }), payload({ value: "normal" }))).toBe(false);
  });
});

describe("isVulnerable — branch 4: AI-provided expectedIndicator", () => {
  it("flags via valid regex match on body", () => {
    expect(
      isVulnerable(result({ body: "uid=1000(user)" }), payload({ expectedIndicator: "uid=\\d+" }))
    ).toBe(true);
  });

  it("falls back to case-insensitive string-includes when the AI provides an invalid regex", () => {
    // Claude has been observed emitting malformed regex. The fallback
    // uses case-insensitive string-includes so a reasonable
    // human-language indicator still works when the regex is wrong.
    // Indicator `)pattern` is invalid regex (unmatched close paren)
    // but is a substring of the body text below, so the fallback
    // hits and returns true. Body without the substring returns false.
    expect(
      isVulnerable(result({ body: "ERROR found in query" }), payload({ expectedIndicator: ")foo" }))
    ).toBe(false);
    expect(
      isVulnerable(
        result({ body: "observed: )pattern in the wild" }),
        payload({ expectedIndicator: ")pattern" })
      )
    ).toBe(true);
  });

  it("does NOT flag when no branch fires and expectedIndicator is empty", () => {
    // The empty-string short-circuit prevents an empty indicator from
    // triggering `new RegExp("")` which matches any string → false-positive.
    expect(isVulnerable(result({ body: "OK" }), payload({ expectedIndicator: "" }))).toBe(false);
  });
});

describe("parsePayloads — JSON extraction", () => {
  it("returns null on text with no JSON object", () => {
    expect(parsePayloads("Sorry, I can't generate payloads for this.")).toBeNull();
  });

  it("returns null on malformed JSON (no throw)", () => {
    expect(parsePayloads('{"payloads": [{"param"')).toBeNull();
  });

  it("parses valid payload JSON", () => {
    const text = JSON.stringify({
      payloads: [
        {
          param: "q",
          value: "' OR 1=1--",
          reasoning: "SQLi OR bypass",
          expectedIndicator: "sql|error",
        },
      ],
    });
    const parsed = parsePayloads(text);
    expect(parsed).not.toBeNull();
    expect(parsed?.payloads).toHaveLength(1);
    expect(parsed?.payloads[0].param).toBe("q");
  });

  it("extracts the JSON object even when prose surrounds it", () => {
    const json = JSON.stringify({ payloads: [] });
    const parsed = parsePayloads(`Here are the payloads:\n\n${json}\n\nLet me know.`);
    expect(parsed).toEqual({ payloads: [] });
  });
});
