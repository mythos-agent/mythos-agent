import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { toolsCheckCommand } from "../tools.js";
import { statsCommand } from "../stats.js";
import { summaryCommand } from "../summary.js";
import { complianceCommand } from "../compliance.js";
import { doctorCommand } from "../doctor.js";
import { quickCommand } from "../quick.js";
import { scoreCommand } from "../score.js";

const DEMO_APP = path.resolve(__dirname, "../../../../demo-vulnerable-app");

/**
 * Smoke tests for CLI commands. The goal is not to verify business logic
 * (that's covered by unit tests on the underlying modules); the goal is to
 * verify each command can be invoked without throwing under normal inputs.
 *
 * A regression that breaks CLI command loading or wiring is caught here
 * before it reaches a user. This is the "Day-1 visitor" smoke test the
 * H1 2026 80% CLI coverage bucket sits on top of.
 */

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;
let tmpDir: string;

beforeEach(() => {
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-cli-smoke-"));
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("CLI smoke tests", () => {
  describe("tools", () => {
    it("runs without throwing and reports installed tool count", async () => {
      await expect(toolsCheckCommand()).resolves.not.toThrow();
      const output = logSpy.mock.calls.flat().join("\n");
      expect(output).toMatch(/shedu tools/);
      // The summary line is "<n>/<m> tools available."
      expect(output).toMatch(/\d+\/\d+ tools available/);
    });
  });

  describe("stats", () => {
    it("handles empty project (no scan results) gracefully", async () => {
      await expect(statsCommand({ path: tmpDir })).resolves.not.toThrow();
      const output = logSpy.mock.calls.flat().join("\n");
      expect(output).toMatch(/shedu stats/);
      expect(output).toMatch(/No scan results yet/);
    });
  });

  describe("summary", () => {
    it("runs against an empty project without throwing", async () => {
      await expect(summaryCommand({ path: tmpDir })).resolves.not.toThrow();
      const output = logSpy.mock.calls.flat().join("\n");
      expect(output.length).toBeGreaterThan(0);
    });
  });

  describe("compliance", () => {
    it("exits gracefully when no scan results exist", async () => {
      await expect(complianceCommand({ path: tmpDir, frameworks: "OWASP" })).resolves.not.toThrow();
      const output = logSpy.mock.calls.flat().join("\n");
      expect(output).toMatch(/No scan results/);
    });
  });

  describe("doctor", () => {
    it("runs health checks against an empty project without throwing", async () => {
      await expect(doctorCommand({ path: tmpDir })).resolves.not.toThrow();
      const output = logSpy.mock.calls.flat().join("\n");
      expect(output).toMatch(/shedu doctor/);
    });
  });

  describe("quick", () => {
    it("runs a quick scan against the demo-vulnerable-app", async () => {
      await expect(quickCommand({ path: DEMO_APP })).resolves.not.toThrow();
      const output = logSpy.mock.calls.flat().join("\n");
      // quick prints scan results; the demo app has known findings
      expect(output.length).toBeGreaterThan(0);
    }, 30_000);
  });

  describe("score", () => {
    it("computes a security score for the demo app without throwing", async () => {
      await expect(scoreCommand({ path: DEMO_APP, json: true })).resolves.not.toThrow();
      // With --json, output is structured; verify at least one log call happened
      expect(logSpy.mock.calls.length).toBeGreaterThan(0);
    }, 30_000);
  });
});
