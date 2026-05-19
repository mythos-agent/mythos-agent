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
import { ciCommand } from "../ci.js";

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
      expect(output).toMatch(/mythos-agent tools/);
      // The summary line is "<n>/<m> tools available."
      expect(output).toMatch(/\d+\/\d+ tools available/);
    });
  });

  describe("stats", () => {
    it("handles empty project (no scan results) gracefully", async () => {
      await expect(statsCommand({ path: tmpDir })).resolves.not.toThrow();
      const output = logSpy.mock.calls.flat().join("\n");
      expect(output).toMatch(/mythos-agent stats/);
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
      expect(output).toMatch(/mythos-agent doctor/);
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

  describe("ci", () => {
    // process.exit returns `never`; vi.spyOn inference fails on never-return
    // functions. Using any avoids the TS2322 assignment error.
    let exitSpy: any; // NOSONAR

    beforeEach(() => {
      // ciCommand calls process.exit — mock to prevent the test process from
      // actually exiting. Return type cast needed because process.exit is typed
      // as () => never.
      exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {}) as () => never);
    });

    afterEach(() => {
      exitSpy.mockRestore();
    });

    it("exits 0 on a clean project (no findings)", async () => {
      // tmpDir is empty — no source files, no vulnerabilities expected.
      await ciCommand({ path: tmpDir, failOn: "none" });
      expect(exitSpy).toHaveBeenCalledWith(0);
      expect(exitSpy).not.toHaveBeenCalledWith(1);
    }, 60_000);

    it("exits 1 when findings meet the fail-on threshold", async () => {
      // Write a file with a weak-hash pattern (createHash("md5")) that
      // CryptoScanner detects. This scanner was NOT in the old 4-scanner list,
      // so finding it proves runScan() is running the full suite.
      const vulnFile = path.join(tmpDir, "crypto-vuln.ts");
      fs.writeFileSync(
        vulnFile,
        `import crypto from "crypto";\nconst h = crypto.createHash("md5").update(data).digest("hex");\n`,
        "utf-8"
      );

      await ciCommand({ path: tmpDir, failOn: "high" });

      // CryptoScanner flags createHash("md5") as severity "high".
      // ciCommand should have called process.exit(1) due to the fail-on check.
      expect(exitSpy).toHaveBeenCalledWith(1);
    }, 60_000);

    it("writes a SARIF file when --sarif is provided", async () => {
      const sarifPath = path.join(tmpDir, "results", "scan.sarif");
      await ciCommand({ path: tmpDir, failOn: "none", sarif: sarifPath });

      expect(fs.existsSync(sarifPath)).toBe(true);
      const sarif = JSON.parse(fs.readFileSync(sarifPath, "utf-8"));
      expect(sarif).toHaveProperty("$schema");
      expect(sarif).toHaveProperty("runs");
      expect(exitSpy).toHaveBeenCalledWith(0);
    }, 60_000);

    it("uses runScan — includes findings from CryptoScanner (not in old 4-scanner list)", async () => {
      // Plant an MD5 weak-hash file so CryptoScanner fires.
      const vulnFile = path.join(tmpDir, "weak-hash.ts");
      fs.writeFileSync(
        vulnFile,
        `const crypto = require("crypto");\nconst hash = crypto.createHash("md5");\n`,
        "utf-8"
      );

      await ciCommand({ path: tmpDir, failOn: "none" });

      // Inspect the saved results to confirm the CryptoScanner finding is present.
      const resultsFile = path.join(tmpDir, ".sphinx", "results.json");
      expect(fs.existsSync(resultsFile)).toBe(true);
      const saved = JSON.parse(fs.readFileSync(resultsFile, "utf-8"));
      const allFindings: Array<{ rule?: string; id?: string }> =
        saved.confirmedVulnerabilities ?? [];
      // CryptoScanner sets rule: "crypto:<rule-id>" and id: "CRYPTO-XXXX"
      const hasCryptoFinding = allFindings.some(
        (f) => (f.rule ?? "").startsWith("crypto:") || (f.id ?? "").startsWith("CRYPTO-")
      );
      expect(hasCryptoFinding).toBe(true);
    }, 60_000);
  });
});
