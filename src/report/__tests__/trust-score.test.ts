import { describe, it, expect } from "vitest";
import { calculateTrustScore } from "../trust-score.js";
import type { Vulnerability, VulnChain } from "../../types/index.js";

function makeVuln(severity: Vulnerability["severity"]): Vulnerability {
  return {
    id: `V-${severity}`,
    rule: `test:${severity}`,
    title: `${severity} vuln`,
    description: "",
    severity,
    category: "test",
    confidence: "high",
    location: { file: "test.ts", line: 1 },
  };
}

function makeChain(severity: VulnChain["severity"]): VulnChain {
  return {
    id: `C-${severity}`,
    title: `${severity} chain`,
    severity,
    vulnerabilities: [],
    narrative: "test",
    impact: "test",
  };
}

describe("calculateTrustScore", () => {
  it("returns 10.0 for empty input", () => {
    expect(calculateTrustScore([], [])).toBe(10);
  });

  it("returns 10.0 when chains is undefined", () => {
    expect(calculateTrustScore([], undefined)).toBe(10);
  });

  it("deducts 2.0 per critical finding", () => {
    expect(calculateTrustScore([makeVuln("critical")], [])).toBe(8.0);
    expect(calculateTrustScore([makeVuln("critical"), makeVuln("critical")], [])).toBe(6.0);
  });

  it("deducts 1.0 per high finding", () => {
    expect(calculateTrustScore([makeVuln("high")], [])).toBe(9.0);
  });

  it("deducts 0.5 per medium finding", () => {
    expect(calculateTrustScore([makeVuln("medium")], [])).toBe(9.5);
  });

  it("deducts 0.2 per low finding", () => {
    expect(calculateTrustScore([makeVuln("low")], [])).toBe(9.8);
  });

  it("does not deduct for info findings", () => {
    expect(calculateTrustScore([makeVuln("info")], [])).toBe(10);
  });

  it("deducts 1.5 per critical chain", () => {
    expect(calculateTrustScore([], [makeChain("critical")])).toBe(8.5);
  });

  it("deducts 1.0 per high chain", () => {
    expect(calculateTrustScore([], [makeChain("high")])).toBe(9.0);
  });

  it("deducts 0.5 per medium chain", () => {
    expect(calculateTrustScore([], [makeChain("medium")])).toBe(9.5);
  });

  it("does not deduct for low chains", () => {
    expect(calculateTrustScore([], [makeChain("low")])).toBe(10);
  });

  it("does not deduct for info chains", () => {
    expect(calculateTrustScore([], [makeChain("info")])).toBe(10);
  });

  it("combines finding and chain penalties", () => {
    // 10 - 2.0 (critical finding) - 1.5 (critical chain) = 6.5
    expect(calculateTrustScore([makeVuln("critical")], [makeChain("critical")])).toBe(6.5);
  });

  it("clamps to 0 — never goes negative", () => {
    // 5 criticals = -10, plus 3 high chains = -3: raw -3, clamped 0
    const vulns = Array.from({ length: 5 }, () => makeVuln("critical"));
    const chains = Array.from({ length: 3 }, () => makeChain("high"));
    expect(calculateTrustScore(vulns, chains)).toBe(0);
  });

  it("clamps to 10 — never exceeds ceiling", () => {
    // No findings, no chains: exactly 10, not above
    expect(calculateTrustScore([], [])).toBe(10);
  });

  it("mixed severity sum is correct", () => {
    // 1 critical (2) + 1 high (1) + 1 medium (0.5) + 1 low (0.2) = 3.7; 10 - 3.7 = 6.3
    const vulns = [makeVuln("critical"), makeVuln("high"), makeVuln("medium"), makeVuln("low")];
    expect(calculateTrustScore(vulns, [])).toBeCloseTo(6.3, 10);
  });

  it("mixed findings + mixed chains", () => {
    // 1 high (1.0) + 1 critical chain (1.5) = 2.5; 10 - 2.5 = 7.5
    expect(calculateTrustScore([makeVuln("high")], [makeChain("critical")])).toBe(7.5);
  });
});
