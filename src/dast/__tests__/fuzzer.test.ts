import { describe, it, expect } from "vitest";

import { checkVulnerable, resultToVulnerability, type FuzzResult } from "../fuzzer.js";
import type { TestPayload } from "../payload-generator.js";

// fuzzer.ts's live HTTP path (`fuzzEndpoints`, `sendPayload`) needs a test
// server to exercise — that would be a pure integration test duplicating
// what we already have for api.ts. The load-bearing *logic* is the
// detection oracle (`checkVulnerable`) and the result-to-Vulnerability
// projection (`resultToVulnerability`); both are exported now and
// testable with constructed inputs.

function payload(overrides: Partial<TestPayload> = {}): TestPayload {
  return {
    category: "sqli",
    name: "test",
    value: "' OR 1=1--",
    detectPattern: /error|sql/i,
    severity: "critical",
    cwe: "CWE-89",
    ...overrides,
  };
}

const emptyHeaders = new Headers();

describe("checkVulnerable — detectPattern matching", () => {
  it("flags vulnerable when payload.detectPattern matches the response body", () => {
    const result = checkVulnerable(
      payload({ detectPattern: /mysql error/i }),
      200,
      "Internal server error: MySQL error near line 1",
      100,
      emptyHeaders
    );
    expect(result.isVuln).toBe(true);
    expect(result.evidence).toContain("vulnerability indicator");
    expect(result.evidence).toContain("mysql error");
  });

  it("does not flag when pattern does not match and no other heuristic fires", () => {
    const result = checkVulnerable(
      payload({ detectPattern: /mysql error/i }),
      200,
      "OK",
      100,
      emptyHeaders
    );
    expect(result.isVuln).toBe(false);
    expect(result.evidence).toBeUndefined();
  });
});

describe("checkVulnerable — time-based blind detection", () => {
  it("flags vulnerable when a Time-based payload's response time exceeds 4500ms", () => {
    // The time-based SQLi payload `WAITFOR DELAY '0:0:5'` forces a 5s
    // delay server-side. checkVulnerable treats >4500ms as confirmation.
    const result = checkVulnerable(
      payload({ name: "Time-based blind", detectPattern: /./ }),
      200,
      "",
      5000,
      emptyHeaders
    );
    // Note: `detectPattern: /./` matches any non-empty body, so the
    // pattern path would only trigger on body "". We test with body=""
    // specifically to isolate the time-based branch.
    expect(result.isVuln).toBe(true);
    expect(result.evidence).toMatch(/5000ms/);
  });

  it("does not flag Time-based payloads under the 4500ms threshold", () => {
    const result = checkVulnerable(
      payload({ name: "Time-based blind", detectPattern: /./ }),
      200,
      "",
      4000,
      emptyHeaders
    );
    expect(result.isVuln).toBe(false);
  });
});

describe("checkVulnerable — open-redirect detection via Location header", () => {
  it("flags when a redirect response points at evil.com", () => {
    const headers = new Headers({ location: "https://evil.com/steal" });
    const result = checkVulnerable(
      payload({ category: "redirect", name: "External redirect", detectPattern: /NEVER_MATCH/ }),
      302,
      "",
      50,
      headers
    );
    expect(result.isVuln).toBe(true);
    expect(result.evidence).toContain("evil.com");
  });

  it("flags a protocol-relative redirect (starts with //)", () => {
    const headers = new Headers({ location: "//other.example/steal" });
    const result = checkVulnerable(
      payload({ category: "redirect", detectPattern: /NEVER_MATCH/ }),
      301,
      "",
      50,
      headers
    );
    expect(result.isVuln).toBe(true);
  });

  it("does NOT flag a redirect to a same-origin path (relative redirect is safe)", () => {
    const headers = new Headers({ location: "/login" });
    const result = checkVulnerable(
      payload({ category: "redirect", detectPattern: /NEVER_MATCH/ }),
      302,
      "",
      50,
      headers
    );
    expect(result.isVuln).toBe(false);
  });
});

describe("checkVulnerable — error-based SQLi detection", () => {
  it("flags sqli payloads when status=500 AND body contains a SQL error signature", () => {
    const result = checkVulnerable(
      payload({ category: "sqli", detectPattern: /NEVER_MATCH/ }),
      500,
      "ERROR: syntax error at position 42 in SELECT query",
      50,
      emptyHeaders
    );
    expect(result.isVuln).toBe(true);
    expect(result.evidence).toMatch(/database error/);
  });

  it("does NOT flag sqli payloads when status=500 but body has no SQL signature", () => {
    const result = checkVulnerable(
      payload({ category: "sqli", detectPattern: /NEVER_MATCH/ }),
      500,
      "Internal server error — please try again",
      50,
      emptyHeaders
    );
    expect(result.isVuln).toBe(false);
  });

  it("does NOT flag sqli payloads when body has SQL signature but status is not 500", () => {
    // 200 + SQL-looking body isn't the error-based SQLi signal; that
    // branch specifically requires 500. Pinning this prevents a
    // refactor from relaxing the status requirement and false-positive
    // flagging on innocuous SQL docs being served over 200.
    const result = checkVulnerable(
      payload({ category: "sqli", detectPattern: /NEVER_MATCH/ }),
      200,
      "This API returns SQL-ish syntax in its docs: SELECT foo FROM bar",
      50,
      emptyHeaders
    );
    expect(result.isVuln).toBe(false);
  });
});

describe("resultToVulnerability — projection", () => {
  const baseResult: FuzzResult = {
    endpoint: "http://localhost:3000/api/search",
    method: "GET",
    payload: payload({ name: "Basic OR bypass", value: "' OR '1'='1" }),
    statusCode: 500,
    responseTime: 234,
    responseBody: "",
    vulnerable: true,
    evidence: "SQL error detected",
  };

  it("formats id as FUZZ-NNNN with zero-padded index", () => {
    expect(resultToVulnerability(baseResult, 0).id).toBe("FUZZ-0001");
    expect(resultToVulnerability(baseResult, 41).id).toBe("FUZZ-0042");
    expect(resultToVulnerability(baseResult, 9999).id).toBe("FUZZ-10000");
  });

  it("tags rule with the dast: prefix + payload category (keeps provenance)", () => {
    const v = resultToVulnerability(baseResult, 0);
    expect(v.rule).toBe("dast:sqli");
    expect(v.category).toBe("dast");
  });

  it("preserves CWE and severity from the payload", () => {
    const v = resultToVulnerability(baseResult, 0);
    expect(v.cwe).toBe("CWE-89");
    expect(v.severity).toBe("critical");
  });

  it("marks confidence=high (DAST confirmation is stronger than pattern match)", () => {
    expect(resultToVulnerability(baseResult, 0).confidence).toBe("high");
  });

  it("uses the endpoint URL as location.file and includes response metadata in the snippet", () => {
    const v = resultToVulnerability(baseResult, 0);
    expect(v.location.file).toBe("http://localhost:3000/api/search");
    expect(v.location.snippet).toContain("GET");
    expect(v.location.snippet).toContain("500");
    expect(v.location.snippet).toContain("234ms");
  });

  it("includes the evidence string in the description when present", () => {
    const v = resultToVulnerability(baseResult, 0);
    expect(v.description).toContain("SQL error detected");
  });

  it("truncates very long payload values to 50 chars in the description", () => {
    const longValue = "X".repeat(200);
    const v = resultToVulnerability({ ...baseResult, payload: payload({ value: longValue }) }, 0);
    // The description should include exactly 50 of the X's, not 200.
    const sliced = longValue.slice(0, 50);
    expect(v.description).toContain(sliced);
    expect(v.description).not.toContain(longValue);
  });
});
