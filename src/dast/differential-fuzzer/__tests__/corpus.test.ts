import { describe, it, expect } from "vitest";
import { loadCorpus } from "../corpus.js";

describe("loadCorpus", () => {
  it("returns a non-empty corpus", () => {
    expect(loadCorpus().length).toBeGreaterThan(20);
  });

  it("every entry has a non-empty family and url", () => {
    for (const e of loadCorpus()) {
      expect(e.family.length).toBeGreaterThan(0);
      expect(e.url.length).toBeGreaterThan(0);
    }
  });

  it("covers all eight confusion families", () => {
    const families = new Set(loadCorpus().map((e) => e.family));
    for (const f of [
      "embedded-at",
      "backslash",
      "missing-slash",
      "whitespace",
      "unicode-idn",
      "control-char",
      "userinfo-port",
      "ip-oddity",
    ]) {
      expect(families.has(f)).toBe(true);
    }
  });

  it("has no two byte-identical entries", () => {
    const urls = loadCorpus().map((e) => e.url);
    expect(new Set(urls).size).toBe(urls.length);
  });
});
