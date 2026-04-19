import { describe, it, expect } from "vitest";

import {
  getPayloads,
  generateTargetedPayloads,
  SQL_INJECTION_PAYLOADS,
  XSS_PAYLOADS,
  COMMAND_INJECTION_PAYLOADS,
  PATH_TRAVERSAL_PAYLOADS,
  SSRF_PAYLOADS,
  OPEN_REDIRECT_PAYLOADS,
} from "../payload-generator.js";

// payload-generator.ts is pure data + two pure selectors — no LLM, no I/O,
// no time dependency. Tests here pin the category routing table and the
// structural shape of each bank of payloads so a future refactor
// (e.g., reorganizing the registry into a map) can't silently drop
// payloads or change the category keying.

describe("getPayloads — unfiltered", () => {
  it("returns every payload from every category when no filter is provided", () => {
    const total =
      SQL_INJECTION_PAYLOADS.length +
      XSS_PAYLOADS.length +
      COMMAND_INJECTION_PAYLOADS.length +
      PATH_TRAVERSAL_PAYLOADS.length +
      SSRF_PAYLOADS.length +
      OPEN_REDIRECT_PAYLOADS.length;
    expect(getPayloads()).toHaveLength(total);
  });

  it("always contains at least one payload in every shipped category", () => {
    // Guards against a future refactor accidentally emptying a bank.
    const categories = new Set(getPayloads().map((p) => p.category));
    expect(categories).toEqual(
      new Set(["sqli", "xss", "cmdi", "path-traversal", "ssrf", "redirect"])
    );
  });
});

describe("getPayloads — filtered", () => {
  it("returns only payloads whose .category matches (sqli)", () => {
    const sqli = getPayloads("sqli");
    expect(sqli.length).toBeGreaterThan(0);
    for (const p of sqli) expect(p.category).toBe("sqli");
    expect(sqli).toEqual(SQL_INJECTION_PAYLOADS);
  });

  it("returns only xss-category payloads when filtered by 'xss'", () => {
    const xss = getPayloads("xss");
    expect(xss.every((p) => p.category === "xss")).toBe(true);
    expect(xss).toEqual(XSS_PAYLOADS);
  });

  it("returns [] for an unknown category (no silent fallback to all)", () => {
    // If a caller typos 'sqlinj' instead of 'sqli', they must get
    // zero payloads rather than the full bank — which would make a
    // typo invisibly fuzz with every payload.
    expect(getPayloads("sqlinj")).toEqual([]);
    expect(getPayloads("definitely-not-a-category")).toEqual([]);
  });
});

describe("generateTargetedPayloads — static-analysis → payload routing", () => {
  it.each<[string, number]>([
    ["injection", SQL_INJECTION_PAYLOADS.length],
    ["sql-injection", SQL_INJECTION_PAYLOADS.length],
    ["xss", XSS_PAYLOADS.length],
    ["command-injection", COMMAND_INJECTION_PAYLOADS.length],
    ["path-traversal", PATH_TRAVERSAL_PAYLOADS.length],
    ["ssrf", SSRF_PAYLOADS.length],
    ["redirect", OPEN_REDIRECT_PAYLOADS.length],
  ])("maps vuln category '%s' to its corresponding payload bank (%d payloads)", (cat, len) => {
    expect(generateTargetedPayloads(cat)).toHaveLength(len);
  });

  it("maps both 'injection' and 'sql-injection' to SQL_INJECTION_PAYLOADS (convenience alias)", () => {
    // The analyzer emits either category name depending on rule; both
    // must route to the same payload bank. Pinning this alias prevents
    // a refactor from breaking one caller silently.
    expect(generateTargetedPayloads("injection")).toEqual(SQL_INJECTION_PAYLOADS);
    expect(generateTargetedPayloads("sql-injection")).toEqual(SQL_INJECTION_PAYLOADS);
  });

  it("returns [] for an unknown vuln category", () => {
    expect(generateTargetedPayloads("unknown")).toEqual([]);
    expect(generateTargetedPayloads("")).toEqual([]);
  });
});

describe("payload structural invariants", () => {
  it("every payload has a compilable detectPattern RegExp", () => {
    // If a RegExp instance is missing .test (e.g., someone swapped a
    // string in by mistake), later `detectPattern.test(body)` throws
    // at runtime on live fuzz — catch it at unit-test time instead.
    for (const p of getPayloads()) {
      expect(p.detectPattern).toBeInstanceOf(RegExp);
      expect(() => p.detectPattern.test("probe")).not.toThrow();
    }
  });

  it("every payload has severity in the allowed {critical, high, medium} set", () => {
    const allowed = new Set(["critical", "high", "medium"]);
    for (const p of getPayloads()) {
      expect(allowed.has(p.severity)).toBe(true);
    }
  });

  it("every payload has a CWE identifier in CWE-NNN format", () => {
    for (const p of getPayloads()) {
      expect(p.cwe).toMatch(/^CWE-\d+$/);
    }
  });
});
