import { describe, it, expect } from "vitest";
import { findAstPattern, inferLanguage } from "../matcher.js";
import { getParser } from "../parser.js";

// First test coverage for src/analysis/ast-matcher/. The variant-hunt
// experiment showed that prompt-only variant analysis can't reliably
// find variants on matched targets; A2's matcher is what closes that
// gap by giving the agent a structural search primitive instead of
// (or alongside) regex-based search_code. These tests pin the
// behavior the agent loop and A3's calibration corpus depend on:
//
//  1. Single-kind matching (the common case for A1's
//     `call_expression`, `new_expression`, `function_declaration` seeds).
//  2. Union-kind matching (retained for hypothetical seeds that
//     genuinely span two real tree-sitter kinds; A1's current seeds
//     all use single real kinds after A3 calibration tightened them).
//  3. Text-predicate AND semantics (predicates narrow a kind match
//     to a specific shape — e.g. callee identifier, parameter name).
//  4. Match cap and parse-error tolerance.
//  5. Language inference from file extension.
//  6. End-to-end shapes for each of the five A1 seed CVEs against
//     synthetic JS/TS code modeled on the upstream vulnerable commit.

describe("inferLanguage — extension routing", () => {
  it.each([
    ["foo.ts", "typescript"],
    ["foo.tsx", "typescript"],
    ["foo.cts", "typescript"],
    ["foo.mts", "typescript"],
    ["foo.js", "javascript"],
    ["foo.jsx", "javascript"],
    ["foo.cjs", "javascript"],
    ["foo.mjs", "javascript"],
    ["foo.TS", "typescript"],
    ["foo.JSX", "javascript"],
  ])("infers %s as %s", (file, lang) => {
    expect(inferLanguage(file)).toBe(lang);
  });

  it.each(["foo.py", "foo.go", "foo.rs", "foo.md", "Makefile", "no-extension"])(
    "returns null for unsupported file %s",
    (file) => {
      expect(inferLanguage(file)).toBeNull();
    }
  );
});

describe("getParser — singleton wiring", () => {
  it("returns a usable Parser for javascript", async () => {
    const parser = await getParser("javascript");
    const tree = parser.parse("const x = 1 + 2;");
    expect(tree).not.toBeNull();
    expect(tree?.rootNode.type).toBe("program");
  });

  it("returns a usable Parser for typescript", async () => {
    const parser = await getParser("typescript");
    const tree = parser.parse("const x: number = 1 + 2;");
    expect(tree).not.toBeNull();
    expect(tree?.rootNode.type).toBe("program");
  });
});

describe("findAstPattern — kind matching", () => {
  it("finds a single-kind match", async () => {
    const matches = await findAstPattern({
      kind: "call_expression",
      source: "foo(1, 2);",
      language: "javascript",
    });
    expect(matches).toHaveLength(1);
    expect(matches[0].kind).toBe("call_expression");
    expect(matches[0].text).toBe("foo(1, 2)");
    expect(matches[0].startLine).toBe(1);
  });

  it("finds multiple matches of the same kind", async () => {
    const matches = await findAstPattern({
      kind: "call_expression",
      source: "foo(1); bar(2); baz(3);",
      language: "javascript",
    });
    expect(matches.length).toBeGreaterThanOrEqual(3);
  });

  it("returns [] when nothing matches", async () => {
    const matches = await findAstPattern({
      kind: "function_declaration",
      source: "const x = 1;",
      language: "javascript",
    });
    expect(matches).toEqual([]);
  });

  it("supports kind unions (array of kinds)", async () => {
    // Demonstrates the kind-union API: a hypothetical seed where
    // either node kind constitutes the same vulnerability shape can
    // be encoded as an array. None of A1's current seeds use this
    // (post A3 calibration), but the API is retained.
    const source = "const a = /abc/; const b = `template ${value}`;";
    const matches = await findAstPattern({
      kind: ["regex", "template_string"],
      source,
      language: "javascript",
    });
    const kinds = matches.map((m) => m.kind).sort();
    expect(kinds).toContain("regex");
    expect(kinds).toContain("template_string");
  });
});

describe("findAstPattern — text predicates", () => {
  const source = `
    foo(1);
    bar(2);
    foo(3);
  `;

  it("narrows kind matches with a single predicate (AND with kind)", async () => {
    const matches = await findAstPattern({
      kind: "call_expression",
      source,
      language: "javascript",
      textPredicates: ["^foo\\("],
    });
    expect(matches).toHaveLength(2);
    expect(matches.every((m) => m.text.startsWith("foo("))).toBe(true);
  });

  it("requires ALL predicates to match (predicate AND semantics)", async () => {
    const matches = await findAstPattern({
      kind: "call_expression",
      source,
      language: "javascript",
      // First predicate matches every foo()/bar()/baz() — second
      // narrows to bar() specifically. AND-semantics means the
      // result is just the bar() call.
      textPredicates: ["\\(", "^bar"],
    });
    expect(matches).toHaveLength(1);
    expect(matches[0].text).toBe("bar(2)");
  });

  it("returns [] when predicates fail to match any kind hit", async () => {
    const matches = await findAstPattern({
      kind: "call_expression",
      source,
      language: "javascript",
      textPredicates: ["nonexistent-symbol"],
    });
    expect(matches).toEqual([]);
  });
});

describe("findAstPattern — caps and edge cases", () => {
  it("respects maxMatches", async () => {
    const source = "a();b();c();d();e();f();g();h();i();j();";
    const matches = await findAstPattern({
      kind: "call_expression",
      source,
      language: "javascript",
      maxMatches: 3,
    });
    expect(matches).toHaveLength(3);
  });

  it("returns positional metadata for downstream tools", async () => {
    const source = "// header\nconsole.log('hi');\n";
    const matches = await findAstPattern({
      kind: "call_expression",
      source,
      language: "javascript",
    });
    expect(matches).toHaveLength(1);
    expect(matches[0].startLine).toBe(2);
    expect(matches[0].endLine).toBe(2);
    expect(matches[0].startColumn).toBe(0);
    expect(matches[0].endColumn).toBeGreaterThan(0);
  });

  it("parses TypeScript-only syntax with the typescript grammar", async () => {
    // Type annotations are TS-only; if the grammar is wired wrong
    // (loading JS instead of TS), this errors or silently misses
    // the function_declaration.
    const matches = await findAstPattern({
      kind: "function_declaration",
      source: "function add(a: number, b: number): number { return a + b; }",
      language: "typescript",
    });
    expect(matches).toHaveLength(1);
    expect(matches[0].kind).toBe("function_declaration");
  });
});

describe("findAstPattern — A1 seed CVE shape coverage", () => {
  // For each of the 5 seed patterns in src/analysis/root-cause/seed-
  // patterns.ts, demonstrate that the matcher catches a synthetic
  // sample modeled on the upstream vulnerable commit when given the
  // appropriate kind + text predicates. These are not full variant
  // searches — they're sanity checks that A2's API is expressive
  // enough to encode each of A1's seeds. A3 will exercise this
  // against actual fix-commit code in the calibration corpus.

  it("CVE-2021-23337 lodash: call_expression to _.template", async () => {
    const matches = await findAstPattern({
      kind: "call_expression",
      source: `
        const _ = require('lodash');
        const compiled = _.template('hi ${"<%= name %>"}', userOptions);
      `,
      language: "javascript",
      textPredicates: ["^_\\.template\\("],
    });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some((m) => m.text.includes("_.template"))).toBe(true);
  });

  it("CVE-2024-45296 path-to-regexp: new_expression on RegExp", async () => {
    const matches = await findAstPattern({
      kind: "new_expression",
      source: `
        function buildPathRe(path) {
          const pattern = path.replace(/[A-Z]/g, ':') + '/?';
          return new RegExp('^' + pattern + '$');
        }
      `,
      language: "javascript",
      textPredicates: ["RegExp"],
    });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].text).toContain("new RegExp");
  });

  it("CVE-2022-25883 semver: template_string used to build a regex", async () => {
    const matches = await findAstPattern({
      kind: "template_string",
      source: ["const part = '[0-9]+';", "const rangeRe = `\\\\s*${part}\\\\s+${part}`;"].join(
        "\n"
      ),
      language: "javascript",
      // Looking for the bug shape: \s* or \s+ adjacent to a ${} slot.
      textPredicates: ["\\\\s[*+]"],
    });
    expect(matches.length).toBeGreaterThan(0);
  });

  it("CVE-2024-28849 follow-redirects: regex literal filtering headers on redirect", async () => {
    // The actual upstream shape (vulnerable commit, index.js line
    // 464) is a regex literal in a redirect handler:
    //   removeMatchingHeaders(/^(?:authorization|cookie)$/i, ...)
    // A3 calibration runs the seeded pattern against this real file.
    const matches = await findAstPattern({
      kind: "regex",
      source: `
        function fetchOnRedirect(req) {
          removeMatchingHeaders(/^(?:authorization|cookie)$/i, req.headers);
        }
      `,
      language: "javascript",
      // Bug shape: regex alternation includes authorization/cookie
      // but omits proxy-authorization. Predicate validates the
      // alternation contains authorization.
      textPredicates: ["authorization"],
    });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].text).toContain("authorization");
    expect(matches[0].text).not.toContain("proxy-authorization");
  });

  it("CVE-2022-23541 jsonwebtoken: function_declaration with secretOrPublicKey param", async () => {
    const matches = await findAstPattern({
      kind: "function_declaration",
      source: `
        function verify(token, secretOrPublicKey, options) {
          // dispatch based on token header
          return doVerify(token, secretOrPublicKey);
        }
      `,
      language: "javascript",
      textPredicates: ["secretOrPublicKey"],
    });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].text).toContain("secretOrPublicKey");
  });
});
