import { describe, it, expect } from "vitest";
import { mutate } from "../mutator.js";
import type { CorpusEntry } from "../corpus.js";

const SEEDS: CorpusEntry[] = [
  { family: "f", url: "http://a.com/" },
  { family: "f", url: "http://b.com/" },
];

describe("mutate", () => {
  it("is deterministic for a fixed seed", () => {
    expect(mutate(SEEDS, 50, 123)).toEqual(mutate(SEEDS, 50, 123));
  });

  it("produces different output for a different seed", () => {
    expect(mutate(SEEDS, 50, 1)).not.toEqual(mutate(SEEDS, 50, 2));
  });

  it("returns exactly `count` inputs", () => {
    expect(mutate(SEEDS, 30, 7)).toHaveLength(30);
  });

  it("includes the raw seed URLs", () => {
    const out = mutate(SEEDS, 30, 7);
    expect(out).toContain("http://a.com/");
    expect(out).toContain("http://b.com/");
  });

  it("produces mutated inputs beyond the raw seeds", () => {
    const out = mutate(SEEDS, 30, 7);
    const mutated = out.filter((u) => u !== "http://a.com/" && u !== "http://b.com/");
    expect(mutated.length).toBeGreaterThan(0);
  });
});
