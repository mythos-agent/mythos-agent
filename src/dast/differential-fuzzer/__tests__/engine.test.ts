import { describe, it, expect } from "vitest";
import { compare, classify } from "../engine.js";
import type { ParserId, ParserResult } from "../types.js";

function results(over: Partial<Record<ParserId, ParserResult>>): Record<ParserId, ParserResult> {
  const base: ParserResult = { hostname: "same.com", protocol: "http:" };
  return {
    "native-url": { ...base, ...over["native-url"] },
    "url-parse": { ...base, ...over["url-parse"] },
    "legacy-url": { ...base, ...over["legacy-url"] },
  };
}

describe("compare", () => {
  it("emits no divergence when all parsers agree", () => {
    expect(compare("http://x", results({}))).toEqual([]);
  });

  it("emits a field divergence when two parsers disagree on hostname", () => {
    const d = compare("http://x", results({ "url-parse": { hostname: "evil.com" } }));
    const host = d.filter((x) => x.kind === "field" && x.field === "hostname");
    expect(host.length).toBeGreaterThan(0);
    expect(host[0].valueA === "evil.com" || host[0].valueB === "evil.com").toBe(true);
  });

  it("emits a hang divergence when one parser hung and another did not", () => {
    const d = compare("http://x", results({ "legacy-url": { hang: true } }));
    expect(d.some((x) => x.kind === "hang")).toBe(true);
  });

  it("emits a throw divergence when one parser threw and another did not", () => {
    const d = compare("http://x", results({ "legacy-url": { error: "bad" } }));
    expect(d.some((x) => x.kind === "throw")).toBe(true);
  });
});

describe("classify", () => {
  it("collapses structurally identical divergences into one class with a count", () => {
    const a = compare("http://1", results({ "url-parse": { hostname: "aaa.aaa" } }));
    const b = compare("http://2", results({ "url-parse": { hostname: "bbb.bbb" } }));
    const classes = classify([...a, ...b]);
    const hostClass = classes.find((c) => c.field === "hostname");
    expect(hostClass).toBeDefined();
    expect(hostClass!.count).toBe(2);
  });
});
