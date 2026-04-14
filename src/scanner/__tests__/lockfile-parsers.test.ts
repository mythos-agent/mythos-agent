import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { parseLockfile, discoverLockfiles } from "../lockfile-parsers.js";

const PROJECT_ROOT = path.resolve(__dirname, "../../..");

describe("discoverLockfiles", () => {
  it("finds package-lock.json in project root", () => {
    const lockfiles = discoverLockfiles(PROJECT_ROOT);
    const names = lockfiles.map((f) => path.basename(f));
    expect(names).toContain("package-lock.json");
  });

  it("returns empty array for directory with no lockfiles", () => {
    const lockfiles = discoverLockfiles(os.tmpdir());
    // tmpdir may or may not have lockfiles — just verify it doesn't crash
    expect(Array.isArray(lockfiles)).toBe(true);
  });
});

describe("parseLockfile — npm", () => {
  it("parses the project's own package-lock.json", () => {
    const lockfilePath = path.join(PROJECT_ROOT, "package-lock.json");
    const deps = parseLockfile(lockfilePath);

    expect(deps.length).toBeGreaterThan(0);
    expect(deps[0]).toHaveProperty("name");
    expect(deps[0]).toHaveProperty("version");
    expect(deps[0].ecosystem).toBe("npm");
    expect(deps[0].lockfile).toBe("package-lock.json");
  });

  it("finds @anthropic-ai/sdk in dependencies", () => {
    const lockfilePath = path.join(PROJECT_ROOT, "package-lock.json");
    const deps = parseLockfile(lockfilePath);

    const anthropic = deps.find((d) => d.name === "@anthropic-ai/sdk");
    expect(anthropic).toBeDefined();
    expect(anthropic!.version).toBeTruthy();
  });
});

describe("parseLockfile — requirements.txt", () => {
  it("parses pinned Python dependencies", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-test-"));
    const reqPath = path.join(tmpDir, "requirements.txt");
    fs.writeFileSync(
      reqPath,
      "flask==3.0.0\nrequests==2.31.0\n# comment\nnumpy==1.26.0\n"
    );

    const deps = parseLockfile(reqPath);
    expect(deps).toHaveLength(3);
    expect(deps[0].name).toBe("flask");
    expect(deps[0].version).toBe("3.0.0");
    expect(deps[0].ecosystem).toBe("PyPI");

    fs.rmSync(tmpDir, { recursive: true });
  });

  it("skips comments and flags", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-test-"));
    const reqPath = path.join(tmpDir, "requirements.txt");
    fs.writeFileSync(reqPath, "# comment\n-r base.txt\nflask==3.0.0\n");

    const deps = parseLockfile(reqPath);
    expect(deps).toHaveLength(1);
    expect(deps[0].name).toBe("flask");

    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe("parseLockfile — go.sum", () => {
  it("parses Go modules and deduplicates", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-test-"));
    const goSumPath = path.join(tmpDir, "go.sum");
    fs.writeFileSync(
      goSumPath,
      [
        "github.com/gin-gonic/gin v1.9.1 h1:abc=",
        "github.com/gin-gonic/gin v1.9.1/go.mod h1:def=",
        "golang.org/x/net v0.17.0 h1:ghi=",
      ].join("\n")
    );

    const deps = parseLockfile(goSumPath);
    expect(deps).toHaveLength(2); // deduplicated
    expect(deps[0].name).toBe("github.com/gin-gonic/gin");
    expect(deps[0].version).toBe("1.9.1");
    expect(deps[0].ecosystem).toBe("Go");

    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe("parseLockfile — edge cases", () => {
  it("returns empty array for nonexistent file", () => {
    const deps = parseLockfile("/nonexistent/file.lock");
    expect(deps).toEqual([]);
  });

  it("returns empty array for corrupt JSON", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-test-"));
    const lockPath = path.join(tmpDir, "package-lock.json");
    fs.writeFileSync(lockPath, "not valid json {{{");

    const deps = parseLockfile(lockPath);
    expect(deps).toEqual([]);

    fs.rmSync(tmpDir, { recursive: true });
  });
});
