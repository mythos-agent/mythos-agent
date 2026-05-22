import { describe, it, expect } from "vitest";
import { createHuntAgentTools } from "../hunt-tools.js";
import { createAgentTools } from "../tools.js";
import { createAdvancedTools } from "../tools-advanced.js";

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
