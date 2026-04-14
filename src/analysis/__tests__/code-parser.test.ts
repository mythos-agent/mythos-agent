import { describe, it, expect } from "vitest";
import path from "node:path";
import { parseCodebase } from "../code-parser.js";

const DEMO_APP = path.resolve(__dirname, "../../../demo-vulnerable-app");

describe("parseCodebase", () => {
  it("parses demo app and finds functions", async () => {
    const map = await parseCodebase(DEMO_APP);
    expect(map.functions.length).toBeGreaterThan(0);
  });

  it("detects Express routes", async () => {
    const map = await parseCodebase(DEMO_APP);
    expect(map.routes.length).toBeGreaterThan(0);

    const methods = map.routes.map((r) => r.method);
    expect(methods).toContain("GET");
    expect(methods).toContain("POST");
  });

  it("extracts imports", async () => {
    const map = await parseCodebase(DEMO_APP);
    expect(map.imports.length).toBeGreaterThan(0);

    const sources = map.imports.map((i) => i.source);
    expect(sources.some((s) => s.includes("express") || s.includes("crypto"))).toBe(true);
  });

  it("finds route paths from demo server", async () => {
    const map = await parseCodebase(DEMO_APP);
    const paths = map.routes.map((r) => r.path);

    expect(paths.some((p) => p.includes("/api/"))).toBe(true);
  });

  it("returns correct file references", async () => {
    const map = await parseCodebase(DEMO_APP);

    for (const func of map.functions) {
      expect(func.file).toBeTruthy();
      expect(func.line).toBeGreaterThan(0);
    }

    for (const route of map.routes) {
      expect(route.file).toBeTruthy();
      expect(route.line).toBeGreaterThan(0);
    }
  });
});
