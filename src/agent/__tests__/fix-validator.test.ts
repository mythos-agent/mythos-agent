import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { FixValidator } from "../fix-validator.js";
import type { MythosConfig, Vulnerability } from "../../types/index.js";

// ---------------------------------------------------------------------------
// Mocking strategy: vi.mock the child_process module so we can assert
// whether spawnSync is called with "npm" or "npx" without executing real
// commands against the scanned repo.
// ---------------------------------------------------------------------------

vi.mock("node:child_process", () => ({
  spawnSync: vi.fn().mockReturnValue({ status: 0, error: undefined }),
}));

// Import after mocking so we get the mocked reference.
import { spawnSync } from "node:child_process";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides: Partial<MythosConfig> = {}): MythosConfig {
  return {
    model: "claude-3-haiku-20240307",
    apiKey: undefined,
    ...overrides,
  } as unknown as MythosConfig;
}

function makeVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "SPX-0001",
    rule: "test:vuln",
    title: "Test Vulnerability",
    description: "A test vulnerability",
    severity: "medium",
    category: "test",
    confidence: "high",
    location: { file: "app.ts", line: 1 },
    ...overrides,
  };
}

/**
 * Create a temporary project directory with a package.json that has a
 * test script, and a target file that matches the patch's original content.
 */
function makeTmpProject(targetFile: string, content: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fix-validator-test-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ scripts: { test: "echo test-ran" } }),
    "utf-8"
  );
  fs.mkdirSync(path.dirname(path.join(dir, targetFile)), { recursive: true });
  fs.writeFileSync(path.join(dir, targetFile), content, "utf-8");
  return dir;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("FixValidator.validate — default options (runProjectTests: false)", () => {
  let tmpDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tmpDir = makeTmpProject("app.ts", "const q = `SELECT * WHERE id = ${userInput}`;");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("does NOT call spawnSync with 'npm' when runProjectTests is omitted (default)", async () => {
    const validator = new FixValidator(makeConfig());
    await validator.validate(tmpDir, makeVuln({ location: { file: "app.ts", line: 1 } }), {
      vulnerabilityId: "SPX-0001",
      file: "app.ts",
      original: "const q = `SELECT * WHERE id = ${userInput}`;",
      fixed: "const q = db.prepare('SELECT * WHERE id = ?').get(userInput);",
      description: "Use parameterized query",
      startLine: 1,
      endLine: 1,
    });

    const spawnMock = vi.mocked(spawnSync);
    const npmCalls = spawnMock.mock.calls.filter(([cmd]) => cmd === "npm" || cmd === "npx");
    expect(npmCalls).toHaveLength(0);
  });

  it("does NOT call spawnSync with 'npm' when runProjectTests is explicitly false", async () => {
    const validator = new FixValidator(makeConfig());
    await validator.validate(
      tmpDir,
      makeVuln({ location: { file: "app.ts", line: 1 } }),
      {
        vulnerabilityId: "SPX-0001",
        file: "app.ts",
        original: "const q = `SELECT * WHERE id = ${userInput}`;",
        fixed: "const q = db.prepare('SELECT * WHERE id = ?').get(userInput);",
        description: "Use parameterized query",
        startLine: 1,
        endLine: 1,
      },
      { runProjectTests: false }
    );

    const spawnMock = vi.mocked(spawnSync);
    const npmCalls = spawnMock.mock.calls.filter(([cmd]) => cmd === "npm" || cmd === "npx");
    expect(npmCalls).toHaveLength(0);
  });

  it("returns status 'partial' and regressionsFree=false when vuln is fixed but no tests ran", async () => {
    const validator = new FixValidator(makeConfig());
    const result = await validator.validate(
      tmpDir,
      makeVuln({ location: { file: "app.ts", line: 1 } }),
      {
        vulnerabilityId: "SPX-0001",
        file: "app.ts",
        original: "const q = `SELECT * WHERE id = ${userInput}`;",
        fixed: "const q = db.prepare('SELECT * WHERE id = ?').get(userInput);",
        description: "Use parameterized query",
        startLine: 1,
        endLine: 1,
      }
    );

    // Vuln pattern removed → vulnerabilityFixed: true
    // Compile and test checks were SKIPPED → regressionsFree must NOT be true
    // and status must be "partial" (not "verified") to avoid overclaiming.
    expect(result.vulnerabilityFixed).toBe(true);
    expect(result.regressionsFree).toBe(false);
    expect(result.status).toBe("partial");
  });

  it("message does NOT claim 'code compiles' or 'existing tests pass' when runProjectTests is false", async () => {
    const validator = new FixValidator(makeConfig());
    const result = await validator.validate(
      tmpDir,
      makeVuln({ location: { file: "app.ts", line: 1 } }),
      {
        vulnerabilityId: "SPX-0001",
        file: "app.ts",
        original: "const q = `SELECT * WHERE id = ${userInput}`;",
        fixed: "const q = db.prepare('SELECT * WHERE id = ?').get(userInput);",
        description: "Use parameterized query",
        startLine: 1,
        endLine: 1,
      }
      // default options — runProjectTests omitted (false)
    );

    expect(result.message).not.toContain("code compiles");
    expect(result.message).not.toContain("existing tests pass");
    expect(result.message).toContain("compilation not checked");
    expect(result.message).toContain("project tests not run (runProjectTests: false)");
  });
});

describe("FixValidator.validate — runProjectTests: true", () => {
  let tmpDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    // Mock returns success (status 0) for all spawns
    vi.mocked(spawnSync).mockReturnValue({ status: 0, error: undefined } as ReturnType<
      typeof spawnSync
    >);
    tmpDir = makeTmpProject("app.ts", "const q = `SELECT * WHERE id = ${userInput}`;");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("DOES call spawnSync with 'npx' (tsc) and 'npm' (test) when runProjectTests is true", async () => {
    const validator = new FixValidator(makeConfig());
    await validator.validate(
      tmpDir,
      makeVuln({ location: { file: "app.ts", line: 1 } }),
      {
        vulnerabilityId: "SPX-0001",
        file: "app.ts",
        original: "const q = `SELECT * WHERE id = ${userInput}`;",
        fixed: "const q = db.prepare('SELECT * WHERE id = ?').get(userInput);",
        description: "Use parameterized query",
        startLine: 1,
        endLine: 1,
      },
      { runProjectTests: true }
    );

    const spawnMock = vi.mocked(spawnSync);
    const npxCalls = spawnMock.mock.calls.filter(([cmd]) => cmd === "npx");
    const npmCalls = spawnMock.mock.calls.filter(([cmd]) => cmd === "npm");

    expect(npxCalls.length).toBeGreaterThan(0);
    expect(npmCalls.length).toBeGreaterThan(0);
  });

  it("passes --ignore-scripts in the npm test invocation", async () => {
    const validator = new FixValidator(makeConfig());
    await validator.validate(
      tmpDir,
      makeVuln({ location: { file: "app.ts", line: 1 } }),
      {
        vulnerabilityId: "SPX-0001",
        file: "app.ts",
        original: "const q = `SELECT * WHERE id = ${userInput}`;",
        fixed: "const q = db.prepare('SELECT * WHERE id = ?').get(userInput);",
        description: "Use parameterized query",
        startLine: 1,
        endLine: 1,
      },
      { runProjectTests: true }
    );

    const spawnMock = vi.mocked(spawnSync);
    const npmTestCalls = spawnMock.mock.calls.filter(
      ([cmd, args]) => cmd === "npm" && Array.isArray(args) && args[0] === "test"
    );

    expect(npmTestCalls.length).toBeGreaterThan(0);
    // --ignore-scripts must be present to prevent lifecycle hooks from firing
    const firstNpmTestArgs = npmTestCalls[0][1] as string[];
    expect(firstNpmTestArgs).toContain("--ignore-scripts");
  });

  it("returns status 'verified', regressionsFree=true, and honest message when runProjectTests is true and all checks pass", async () => {
    // spawnSync is already mocked to return { status: 0 } in beforeEach
    const validator = new FixValidator(makeConfig());
    const result = await validator.validate(
      tmpDir,
      makeVuln({ location: { file: "app.ts", line: 1 } }),
      {
        vulnerabilityId: "SPX-0001",
        file: "app.ts",
        original: "const q = `SELECT * WHERE id = ${userInput}`;",
        fixed: "const q = db.prepare('SELECT * WHERE id = ?').get(userInput);",
        description: "Use parameterized query",
        startLine: 1,
        endLine: 1,
      },
      { runProjectTests: true }
    );

    expect(result.vulnerabilityFixed).toBe(true);
    expect(result.regressionsFree).toBe(true);
    expect(result.status).toBe("verified");
    // Message must reflect the real checks, not the skipped-check fragments
    expect(result.message).toContain("code compiles");
    expect(result.message).toContain("existing tests pass");
    expect(result.message).not.toContain("compilation not checked");
    expect(result.message).not.toContain("project tests not run");
  });
});
