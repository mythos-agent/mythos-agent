import { describe, it, expect } from "vitest";
import { findUnmitigatedMatch, type JwtRule } from "../jwt-scanner.js";

const baseRule = {
  id: "t",
  title: "",
  description: "",
  severity: "medium" as const,
  cwe: "",
};

describe("findUnmitigatedMatch", () => {
  it("returns null when no pattern matches", () => {
    const rule: JwtRule = { ...baseRule, patterns: [/NOMATCH/g] };
    expect(findUnmitigatedMatch(rule, "no match here", ["no match here"])).toBeNull();
  });

  it("returns the match when a single pattern fires with no mitigationCheck", () => {
    const rule: JwtRule = { ...baseRule, patterns: [/HIT/g] };
    const content = "line1\nHIT here\nline3";
    const m = findUnmitigatedMatch(rule, content, content.split("\n"));
    expect(m).not.toBeNull();
    expect(m!.line).toBe(2);
  });

  it("suppresses a single-pattern match when mitigationCheck returns true", () => {
    const rule: JwtRule = {
      ...baseRule,
      patterns: [/HIT/g],
      mitigationCheck: (lines, ln) => lines[ln - 1]?.includes("SAFE") ?? false,
    };
    expect(findUnmitigatedMatch(rule, "HIT SAFE here", ["HIT SAFE here"])).toBeNull();
  });

  // Regression test for issue #69: multi-pattern + mitigationCheck must
  // fall through to the next pattern when an earlier pattern's match is
  // mitigated, instead of dropping the rule entirely.
  it("falls through to pattern[1] when pattern[0] match is mitigated", () => {
    const rule: JwtRule = {
      ...baseRule,
      id: "multi-pattern-mitigated",
      patterns: [/FIRST/g, /SECOND/g],
      mitigationCheck: (lines, ln) => lines[ln - 1]?.includes("SAFE") ?? false,
    };
    const content = ["FIRST SAFE here", "SECOND here"].join("\n");
    const m = findUnmitigatedMatch(rule, content, content.split("\n"));
    expect(m).not.toBeNull();
    expect(m!.line).toBe(2);
  });

  it("returns null when every multi-pattern match is mitigated", () => {
    const rule: JwtRule = {
      ...baseRule,
      patterns: [/FIRST/g, /SECOND/g],
      mitigationCheck: (lines, ln) => lines[ln - 1]?.includes("SAFE") ?? false,
    };
    const content = ["FIRST SAFE here", "SECOND SAFE here"].join("\n");
    expect(findUnmitigatedMatch(rule, content, content.split("\n"))).toBeNull();
  });

  it("prefers the earliest unmitigated pattern over later patterns", () => {
    const rule: JwtRule = {
      ...baseRule,
      patterns: [/FIRST/g, /SECOND/g],
    };
    const content = ["SECOND here", "FIRST here"].join("\n");
    const m = findUnmitigatedMatch(rule, content, content.split("\n"));
    expect(m).not.toBeNull();
    expect(m!.line).toBe(2);
  });
});
