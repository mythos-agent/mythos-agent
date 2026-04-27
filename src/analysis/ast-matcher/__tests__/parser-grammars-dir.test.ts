import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { findGrammarsDir } from "../parser.js";

// Regression test for the A3b-surfaced bug: the parser's grammar-dir
// resolution was a fixed `../../../assets/grammars` hop count, which
// works in the source layout (`src/analysis/ast-matcher/`) and in the
// regular `dist/` build but NOT in `dist-benchmarks/src/...` (which
// preserves the `src/` prefix). Symptom: every find_ast_pattern call
// from the calibration harness hit Language.load() failures, the
// agent reported "AST engine has file access issues," and fell back
// to regex search — defeating the whole point of A2.
//
// Fix: walk up looking for any `assets/grammars` directory. These
// tests verify the walk-up against synthetic layouts so we catch
// regressions without depending on the real on-disk repo.

describe("findGrammarsDir", () => {
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-grammars-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("finds assets/grammars one level up from a 'src-like' module location", () => {
    // Mimics the source layout: tmpRoot/src/analysis/ast-matcher/parser.ts
    // with assets/grammars at tmpRoot/assets/grammars.
    const moduleDir = path.join(tmpRoot, "src", "analysis", "ast-matcher");
    fs.mkdirSync(moduleDir, { recursive: true });
    const grammarsDir = path.join(tmpRoot, "assets", "grammars");
    fs.mkdirSync(grammarsDir, { recursive: true });

    expect(findGrammarsDir(moduleDir)).toBe(grammarsDir);
  });

  it("finds assets/grammars from the deeper dist-benchmarks layout (the original bug)", () => {
    // Mimics the broken layout: tmpRoot/dist-benchmarks/src/analysis/
    // ast-matcher/parser.js with assets/grammars at tmpRoot/assets/
    // grammars (one extra hop up). Pre-fix, the fixed `../../../`
    // resolution landed inside dist-benchmarks/ and missed.
    const moduleDir = path.join(tmpRoot, "dist-benchmarks", "src", "analysis", "ast-matcher");
    fs.mkdirSync(moduleDir, { recursive: true });
    const grammarsDir = path.join(tmpRoot, "assets", "grammars");
    fs.mkdirSync(grammarsDir, { recursive: true });

    expect(findGrammarsDir(moduleDir)).toBe(grammarsDir);
  });

  it("prefers the closest assets/grammars when multiple are reachable", () => {
    // If a build copies assets/grammars next to the compiled output
    // AND the repo root also has one, prefer the closer one — that's
    // the intended bundle for the running module.
    const moduleDir = path.join(tmpRoot, "outer", "inner", "parser");
    fs.mkdirSync(moduleDir, { recursive: true });
    const closeGrammars = path.join(tmpRoot, "outer", "assets", "grammars");
    const farGrammars = path.join(tmpRoot, "assets", "grammars");
    fs.mkdirSync(closeGrammars, { recursive: true });
    fs.mkdirSync(farGrammars, { recursive: true });

    expect(findGrammarsDir(moduleDir)).toBe(closeGrammars);
  });

  it("throws a descriptive error when assets/grammars cannot be located", () => {
    const moduleDir = path.join(tmpRoot, "no", "grammars", "anywhere");
    fs.mkdirSync(moduleDir, { recursive: true });

    // Don't create assets/grammars anywhere — walk should run to the
    // filesystem root and throw.
    expect(() => findGrammarsDir(moduleDir)).toThrow(/assets\/grammars/);
  });
});
