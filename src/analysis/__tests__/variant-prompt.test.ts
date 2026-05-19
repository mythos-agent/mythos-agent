import { describe, it, expect } from "vitest";
import { buildVariantSystem, resolvePromptVariant } from "../variant-prompt.js";

// The fix-A isolation experiment (docs/research/2026-05-19-qwen-fix-a-isolation.md)
// needs three system-prompt arms. These tests pin the structural
// differences the experiment depends on: control has no workflow
// directive, variant-a keeps the numbered list but drops the verbatim
// `variants: []` give-up token, variant-b is a single sentence with no
// list. All three must share the same base prompt.

describe("buildVariantSystem", () => {
  it("control has no workflow directive but keeps the base sections", () => {
    const p = buildVariantSystem("control");
    expect(p).not.toContain("## Workflow — REQUIRED");
    expect(p).toContain("## How Variant Analysis Works");
    expect(p).toContain("## Output Format");
  });

  it("variant-a keeps the numbered workflow list", () => {
    const p = buildVariantSystem("variant-a");
    expect(p).toContain("## Workflow — REQUIRED");
    expect(p).toContain("1. Identify the root cause");
    expect(p).toContain("2. Call `find_ast_pattern`");
    expect(p).toContain("3. Only after a tool call has returned");
  });

  it("variant-a drops the verbatim `variants: []` give-up token", () => {
    const p = buildVariantSystem("variant-a");
    // The 2026-05-12 full-A directive said: Emitting `variants: []`
    // without calling any search tool ... — variant-a must NOT.
    expect(p).not.toContain("Emitting `variants: []`");
    expect(p).not.toContain("An empty `variants` array");
    expect(p).toContain("A result with no findings is valid");
  });

  it("variant-b has the workflow directive but no numbered list", () => {
    const p = buildVariantSystem("variant-b");
    expect(p).toContain("## Workflow — REQUIRED");
    expect(p).toContain("you MUST call `find_ast_pattern`");
    expect(p).not.toContain("1. Identify the root cause");
    expect(p).not.toContain("Emitting `variants: []`");
  });

  it("all three arms share the same base head and tail", () => {
    const arms = [
      buildVariantSystem("control"),
      buildVariantSystem("variant-a"),
      buildVariantSystem("variant-b"),
    ];
    for (const p of arms) {
      expect(p.startsWith("You are a variant analysis engine,")).toBe(true);
      expect(p.endsWith("indistinguishable\nfrom a clean miss.")).toBe(true);
    }
  });
});

describe("resolvePromptVariant", () => {
  it("treats unset and empty string as control", () => {
    expect(resolvePromptVariant(undefined)).toBe("control");
    expect(resolvePromptVariant("")).toBe("control");
  });

  it("passes through each recognized variant", () => {
    expect(resolvePromptVariant("control")).toBe("control");
    expect(resolvePromptVariant("variant-a")).toBe("variant-a");
    expect(resolvePromptVariant("variant-b")).toBe("variant-b");
  });

  it("throws on an unrecognized value, naming the bad value", () => {
    expect(() => resolvePromptVariant("varient-a")).toThrow(/varient-a/);
  });
});
