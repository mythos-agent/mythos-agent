import { describe, it, expect, afterEach, beforeEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { findConfigFile, loadConfig, writeConfig } from "../config.js";

// Tests here also cover the 4.0 branding-alias layer: `.mythos.yml` /
// `MYTHOS_*` envs / `.mythos/**` excludes are the canonical surfaces, but
// `.sphinx.yml` and `SPHINX_*` must keep working through 3.x.

const tmpDirs: string[] = [];
const envSnapshot: Record<string, string | undefined> = {};

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-config-"));
  tmpDirs.push(dir);
  return dir;
}

function snapshotEnv(...keys: string[]): void {
  for (const k of keys) {
    envSnapshot[k] = process.env[k];
    delete process.env[k];
  }
}

beforeEach(() => {
  // Isolate each test from the runner's real environment.
  snapshotEnv(
    "MYTHOS_API_KEY",
    "SPHINX_API_KEY",
    "ANTHROPIC_API_KEY",
    "MYTHOS_MODEL",
    "SPHINX_MODEL"
  );
});

afterEach(() => {
  for (const [k, v] of Object.entries(envSnapshot)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    delete envSnapshot[k];
  }
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

describe("findConfigFile — canonical vs legacy preference", () => {
  it("returns .mythos.yml when it exists (preferred canonical name)", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, ".mythos.yml"), "model: foo\n");
    const found = findConfigFile(dir);
    expect(found).toBe(path.join(dir, ".mythos.yml"));
  });

  it("falls back to .sphinx.yml when only the legacy name exists (3.x back-compat)", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, ".sphinx.yml"), "model: foo\n");
    const found = findConfigFile(dir);
    expect(found).toBe(path.join(dir, ".sphinx.yml"));
  });

  it("prefers .mythos.yml over .sphinx.yml when both exist (migration signal)", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, ".mythos.yml"), "model: new\n");
    fs.writeFileSync(path.join(dir, ".sphinx.yml"), "model: old\n");
    const found = findConfigFile(dir);
    expect(found).toBe(path.join(dir, ".mythos.yml"));
  });

  it("walks up the directory tree and returns the first config found", () => {
    const root = tempDir();
    const nested = path.join(root, "a", "b", "c");
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(root, ".mythos.yml"), "model: root\n");
    const found = findConfigFile(nested);
    expect(found).toBe(path.join(root, ".mythos.yml"));
  });
});

describe("loadConfig — env-var back-compat", () => {
  it("MYTHOS_API_KEY is preferred over SPHINX_API_KEY when both are set", () => {
    const dir = tempDir();
    process.env.MYTHOS_API_KEY = "mythos-key";
    process.env.SPHINX_API_KEY = "sphinx-key";
    const cfg = loadConfig(dir);
    expect(cfg.apiKey).toBe("mythos-key");
  });

  it("SPHINX_API_KEY is still accepted when MYTHOS_API_KEY is absent", () => {
    const dir = tempDir();
    process.env.SPHINX_API_KEY = "sphinx-only";
    const cfg = loadConfig(dir);
    expect(cfg.apiKey).toBe("sphinx-only");
  });

  it("ANTHROPIC_API_KEY applies only when no mythos/sphinx env var is set", () => {
    const dir = tempDir();
    process.env.ANTHROPIC_API_KEY = "anthropic-key";
    process.env.SPHINX_API_KEY = "sphinx-key";
    const cfg = loadConfig(dir);
    // SPHINX takes priority over ANTHROPIC because the user opted into
    // project-scoped configuration with the SPHINX_* var.
    expect(cfg.apiKey).toBe("sphinx-key");
  });

  it("MYTHOS_MODEL overrides SPHINX_MODEL", () => {
    const dir = tempDir();
    process.env.MYTHOS_MODEL = "claude-4-7";
    process.env.SPHINX_MODEL = "claude-3-5";
    const cfg = loadConfig(dir);
    expect(cfg.model).toBe("claude-4-7");
  });
});

describe("loadConfig — default excludes", () => {
  it("default config's scan.exclude includes both .mythos/** and .sphinx/**", () => {
    const dir = tempDir();
    const cfg = loadConfig(dir);
    expect(cfg.scan.exclude).toContain(".mythos/**");
    expect(cfg.scan.exclude).toContain(".sphinx/**");
  });
});

describe("writeConfig — canonical filename", () => {
  it("writes to .mythos.yml (the canonical name), not .sphinx.yml", () => {
    const dir = tempDir();
    writeConfig(dir, { model: "foo", provider: "anthropic" });
    expect(fs.existsSync(path.join(dir, ".mythos.yml"))).toBe(true);
    expect(fs.existsSync(path.join(dir, ".sphinx.yml"))).toBe(false);
  });

  it("does not remove an existing .sphinx.yml (non-destructive migration)", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, ".sphinx.yml"), "model: legacy\n");
    writeConfig(dir, { model: "new", provider: "anthropic" });
    expect(fs.existsSync(path.join(dir, ".mythos.yml"))).toBe(true);
    // The legacy file is left in place; users can delete it manually once
    // they've verified the new one works.
    expect(fs.existsSync(path.join(dir, ".sphinx.yml"))).toBe(true);
  });
});
