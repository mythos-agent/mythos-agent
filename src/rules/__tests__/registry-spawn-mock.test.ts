/**
 * Focused tests for Fix 1: installRulePack spawnSync exit-status check.
 *
 * Separated from registry.test.ts because vi.mock("node:child_process", ...)
 * must be hoisted to the top of the module in ESM, and the main registry
 * tests deliberately avoid mocking child_process.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Hoist the child_process mock BEFORE importing the module under test.
vi.mock("node:child_process", () => ({
  spawnSync: vi
    .fn()
    .mockReturnValue({ pid: 0, output: [], stdout: "", stderr: "", status: 0, signal: null }),
}));

import { spawnSync } from "node:child_process";
import { installRulePack } from "../registry.js";

const tmpDirs: string[] = [];

function tempProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-registry-spawn-"));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.mocked(spawnSync).mockReset();
  // Restore default success return for tests that don't override it.
  vi.mocked(spawnSync).mockReturnValue({
    pid: 0,
    output: [],
    stdout: "",
    stderr: "",
    status: 0,
    signal: null,
  } as ReturnType<typeof spawnSync>);

  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

describe("installRulePack — spawnSync exit-status check (Fix 1)", () => {
  it("throws when npm pack exits with status 1", async () => {
    vi.mocked(spawnSync).mockReturnValueOnce({
      pid: 0,
      output: [],
      stdout: "",
      stderr: "E404 Not found: mythos-agent-rules-no-such-pack",
      status: 1,
      signal: null,
    } as ReturnType<typeof spawnSync>);

    const project = tempProject();
    await expect(installRulePack("no-such-pack", project)).rejects.toThrow(/npm pack failed/);
  });

  it("throws when npm pack returns an error object (e.g. ENOENT — npm not found)", async () => {
    vi.mocked(spawnSync).mockReturnValueOnce({
      pid: 0,
      output: [],
      stdout: "",
      stderr: "",
      status: null,
      signal: null,
      error: new Error("spawnSync npm ENOENT"),
    } as unknown as ReturnType<typeof spawnSync>);

    const project = tempProject();
    await expect(installRulePack("my-pack", project)).rejects.toThrow(/npm pack failed/);
  });

  it("throws when tar exits with status 1 (npm pack succeeded, tar failed)", async () => {
    // First call (npm pack): succeed and write a fake tarball so the
    // tarball-find step passes.
    vi.mocked(spawnSync).mockImplementationOnce((_cmd: any, args: any) => {
      // The pack-destination arg is args[2] for "npm pack <pkg> --pack-destination <dir>"
      const destIdx = (args as string[]).indexOf("--pack-destination");
      const destDir = destIdx >= 0 ? (args as string[])[destIdx + 1] : "";
      if (destDir) {
        fs.mkdirSync(destDir, { recursive: true });
        fs.writeFileSync(path.join(destDir, "mythos-agent-rules-my-pack-1.0.0.tgz"), "fake");
      }
      return { pid: 0, output: [], stdout: "", stderr: "", status: 0, signal: null } as ReturnType<
        typeof spawnSync
      >;
    });

    // Second call (tar): fail
    vi.mocked(spawnSync).mockReturnValueOnce({
      pid: 0,
      output: [],
      stdout: "",
      stderr: "tar: Unexpected EOF",
      status: 1,
      signal: null,
    } as ReturnType<typeof spawnSync>);

    const project = tempProject();
    await expect(installRulePack("my-pack", project)).rejects.toThrow(/tar extraction failed/);
  });
});
