import { describe, it, expect, vi } from "vitest";
import { createHuntAgentTools, executeHuntToolCall } from "../hunt-tools.js";
import { createAgentTools } from "../tools.js";
import { createAdvancedTools } from "../tools-advanced.js";

// Stub the heavy codebase-parse step so the routing tests run instantly.
// createAdvancedTools is kept real (it is synchronous and has no side
// effects) so the existing createHuntAgentTools tests are unaffected.
vi.mock("../tools-advanced.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../tools-advanced.js")>();
  return {
    ...real,
    executeAdvancedToolCall: vi.fn().mockResolvedValue("__advanced_executor_called__"),
  };
});

describe("createHuntAgentTools", () => {
  it("includes every basic tool and every advanced tool", () => {
    const names = new Set(createHuntAgentTools("/tmp/x").map((t) => t.name));
    for (const t of createAgentTools("/tmp/x")) expect(names.has(t.name)).toBe(true);
    for (const t of createAdvancedTools("/tmp/x")) expect(names.has(t.name)).toBe(true);
  });

  it("exposes both a basic tool (read_file) and an advanced tool (list_functions)", () => {
    const names = createHuntAgentTools("/tmp/x").map((t) => t.name);
    expect(names).toContain("read_file");
    expect(names).toContain("list_functions");
  });
});

describe("executeHuntToolCall", () => {
  it("routes an unknown tool name to the basic executor", async () => {
    const result = await executeHuntToolCall(process.cwd(), "no_such_tool", {});
    expect(result).toBe("Unknown tool: no_such_tool");
  });

  it("routes an advanced tool name to the advanced executor", async () => {
    // list_functions is an advanced tool; the advanced executor never
    // returns the basic executor's "Unknown tool:" string.
    const result = await executeHuntToolCall(process.cwd(), "list_functions", {});
    expect(result).not.toContain("Unknown tool:");
  });

  it("routes a basic tool name to the basic executor", async () => {
    // read_file is a basic tool; routing to the basic executor means it
    // attempts the read rather than returning "Unknown tool:".
    const result = await executeHuntToolCall(process.cwd(), "read_file", {
      file_path: "package.json",
    });
    expect(result).not.toContain("Unknown tool:");
  });
});
