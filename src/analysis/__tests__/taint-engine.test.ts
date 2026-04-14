import { describe, it, expect } from "vitest";
import path from "node:path";
import { parseCodebase } from "../code-parser.js";
import { buildCallGraph } from "../call-graph.js";
import { runTaintAnalysis, taintFlowsToVulnerabilities } from "../taint-engine.js";

const DEMO_APP = path.resolve(__dirname, "../../../demo-vulnerable-app");

describe("runTaintAnalysis", () => {
  it("finds taint flows in demo app", async () => {
    const map = await parseCodebase(DEMO_APP);
    const graph = buildCallGraph(map, DEMO_APP);
    const flows = runTaintAnalysis(map, graph, DEMO_APP);

    expect(flows.length).toBeGreaterThan(0);
  });

  it("identifies source types", async () => {
    const map = await parseCodebase(DEMO_APP);
    const graph = buildCallGraph(map, DEMO_APP);
    const flows = runTaintAnalysis(map, graph, DEMO_APP);

    const sourceTypes = [...new Set(flows.map((f) => f.source.type))];
    expect(sourceTypes.length).toBeGreaterThan(0);
    expect(sourceTypes.some((t) => t.includes("http") || t.includes("param"))).toBe(true);
  });

  it("identifies sink types", async () => {
    const map = await parseCodebase(DEMO_APP);
    const graph = buildCallGraph(map, DEMO_APP);
    const flows = runTaintAnalysis(map, graph, DEMO_APP);

    const sinkTypes = [...new Set(flows.map((f) => f.sink.type))];
    expect(sinkTypes.length).toBeGreaterThan(0);
  });

  it("marks sanitized vs unsanitized flows", async () => {
    const map = await parseCodebase(DEMO_APP);
    const graph = buildCallGraph(map, DEMO_APP);
    const flows = runTaintAnalysis(map, graph, DEMO_APP);

    // Demo app has NO sanitization, so most flows should be unsanitized
    const unsanitized = flows.filter((f) => !f.sanitized);
    expect(unsanitized.length).toBeGreaterThan(0);
  });

  it("assigns TAINT- prefixed IDs", async () => {
    const map = await parseCodebase(DEMO_APP);
    const graph = buildCallGraph(map, DEMO_APP);
    const flows = runTaintAnalysis(map, graph, DEMO_APP);

    for (const f of flows) {
      expect(f.id).toMatch(/^TAINT-\d{3}$/);
    }
  });
});

describe("taintFlowsToVulnerabilities", () => {
  it("converts unsanitized flows to vulnerabilities", async () => {
    const map = await parseCodebase(DEMO_APP);
    const graph = buildCallGraph(map, DEMO_APP);
    const flows = runTaintAnalysis(map, graph, DEMO_APP);
    const vulns = taintFlowsToVulnerabilities(flows);

    expect(vulns.length).toBeGreaterThan(0);

    for (const v of vulns) {
      expect(v.id).toMatch(/^TAINT-/);
      expect(v.rule).toMatch(/^taint:/);
      expect(v.severity).toBeTruthy();
      expect(v.location.file).toBeTruthy();
    }
  });

  it("excludes sanitized flows from vulnerabilities", async () => {
    const map = await parseCodebase(DEMO_APP);
    const graph = buildCallGraph(map, DEMO_APP);
    const flows = runTaintAnalysis(map, graph, DEMO_APP);
    const vulns = taintFlowsToVulnerabilities(flows);

    // Vulns should only come from unsanitized flows
    const unsanitizedCount = flows.filter((f) => !f.sanitized).length;
    expect(vulns.length).toBe(unsanitizedCount);
  });
});
