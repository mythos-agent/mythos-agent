import { describe, it, expect } from "vitest";
import {
  createAgentTools,
  resolveFindAstKindDoc,
  KIND_DOC_BASELINE,
  KIND_DOC_WORKED_EXAMPLES,
} from "../tools.js";

// The fix-C isolation experiment (docs/research/2026-05-19-qwen-fix-c-on-variant-b.md)
// makes the find_ast_pattern `kind` schema description selectable via
// MYTHOS_FIND_AST_KIND_DOC. These tests pin the resolver behavior and
// the two description variants. Tests run with the env var unset, so
// the module-load default resolves to "baseline".

describe("resolveFindAstKindDoc", () => {
  it("treats unset and empty string as baseline", () => {
    expect(resolveFindAstKindDoc(undefined)).toBe("baseline");
    expect(resolveFindAstKindDoc("")).toBe("baseline");
  });

  it("passes through recognized values", () => {
    expect(resolveFindAstKindDoc("baseline")).toBe("baseline");
    expect(resolveFindAstKindDoc("worked-examples")).toBe("worked-examples");
  });

  it("throws on an unrecognized value, naming the bad value", () => {
    expect(() => resolveFindAstKindDoc("worked_examples")).toThrow(/worked_examples/);
  });
});

describe("find_ast_pattern kind descriptions", () => {
  it("baseline is the terse description, no worked examples", () => {
    expect(KIND_DOC_BASELINE).toContain("tree-sitter node kind to match");
    expect(KIND_DOC_BASELINE).not.toContain("Pick the kind that holds");
  });

  it("worked-examples lists the header-allowlist shape that targets mode C", () => {
    expect(KIND_DOC_WORKED_EXAMPLES).toContain("Pick the kind that holds the LITERAL TEXT");
    expect(KIND_DOC_WORKED_EXAMPLES).toContain("Header allowlist/denylist as inline strings");
    expect(KIND_DOC_WORKED_EXAMPLES).toContain('(NOT "regex"');
  });
});

describe("createAgentTools wiring", () => {
  it("find_ast_pattern's kind description is the baseline doc when env is unset", () => {
    const tools = createAgentTools(".");
    const findAst = tools.find((t) => t.name === "find_ast_pattern");
    expect(findAst).toBeDefined();
    const schema = findAst!.input_schema as {
      properties: { kind: { description: string } };
    };
    expect(schema.properties.kind.description).toBe(KIND_DOC_BASELINE);
  });
});
