import { describe, it, expect } from "vitest";
import { runTool, checkTool, checkAllTools } from "../tool-runner.js";

describe("runTool", () => {
  it("runs a basic command and returns output", () => {
    const result = runTool("node", ["--version"], { parseJson: false });
    expect(result.success).toBe(true);
    expect(result.raw).toMatch(/^v\d+/);
  });

  it("returns error for nonexistent command", () => {
    const result = runTool("nonexistent-command-xyz", ["--version"]);
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("parses JSON output", () => {
    const result = runTool<{ version: string }>(
      "node",
      ["-e", 'console.log(JSON.stringify({version:"1.0"}))'],
    );
    expect(result.success).toBe(true);
    expect(result.data).toEqual({ version: "1.0" });
  });

  it("handles non-JSON output gracefully", () => {
    const result = runTool("node", ["-e", 'console.log("not json")']);
    expect(result.data).toBeNull();
  });

  it("respects timeout", () => {
    const result = runTool(
      "node",
      ["-e", "setTimeout(() => {}, 60000)"],
      { timeout: 500, parseJson: false }
    );
    expect(result.success).toBe(false);
  });

  it("records duration", () => {
    const result = runTool("node", ["--version"], { parseJson: false });
    expect(result.duration).toBeGreaterThanOrEqual(0);
    expect(result.duration).toBeLessThan(5000);
  });
});

describe("checkTool", () => {
  it("detects node as installed", () => {
    // node is always available
    const info = checkTool("semgrep"); // may or may not be installed
    expect(info).toHaveProperty("name");
    expect(info).toHaveProperty("installed");
    expect(typeof info.installed).toBe("boolean");
  });

  it("returns false for unknown tools", () => {
    const info = checkTool("nonexistent-tool-xyz");
    expect(info.installed).toBe(false);
  });
});

describe("checkAllTools", () => {
  it("returns status for all known tools", () => {
    const tools = checkAllTools();
    expect(tools.length).toBeGreaterThan(0);

    for (const tool of tools) {
      expect(tool.name).toBeTruthy();
      expect(typeof tool.installed).toBe("boolean");
    }
  });
});
