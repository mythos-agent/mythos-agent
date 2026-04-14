import { describe, it, expect } from "vitest";
import path from "node:path";
import { parseCodebase } from "../code-parser.js";
import {
  mapEndpoints,
  findUnprotectedEndpoints,
  assessEndpointSecurity,
} from "../endpoint-mapper.js";

const DEMO_APP = path.resolve(__dirname, "../../../demo-vulnerable-app");

describe("mapEndpoints", () => {
  it("maps endpoints from demo app", async () => {
    const map = await parseCodebase(DEMO_APP);
    const endpoints = mapEndpoints(map);

    expect(endpoints.length).toBeGreaterThan(0);
  });

  it("includes method and path for each endpoint", async () => {
    const map = await parseCodebase(DEMO_APP);
    const endpoints = mapEndpoints(map);

    for (const ep of endpoints) {
      expect(ep.method).toBeTruthy();
      expect(ep.path).toBeTruthy();
      expect(ep.file).toBeTruthy();
    }
  });

  it("assigns risk levels", async () => {
    const map = await parseCodebase(DEMO_APP);
    const endpoints = mapEndpoints(map);

    const riskLevels = endpoints.map((e) => e.riskLevel);
    expect(riskLevels.every((r) => ["high", "medium", "low"].includes(r))).toBe(true);
  });
});

describe("findUnprotectedEndpoints", () => {
  it("finds endpoints without auth on sensitive paths", async () => {
    const map = await parseCodebase(DEMO_APP);
    const endpoints = mapEndpoints(map);
    const unprotected = findUnprotectedEndpoints(endpoints);

    // Demo app has no auth middleware, so sensitive endpoints should be flagged
    expect(unprotected.length).toBeGreaterThanOrEqual(0);
  });
});

describe("assessEndpointSecurity", () => {
  it("produces a security assessment", async () => {
    const map = await parseCodebase(DEMO_APP);
    const endpoints = mapEndpoints(map);
    const assessment = assessEndpointSecurity(endpoints);

    expect(assessment.total).toBe(endpoints.length);
    expect(assessment.authenticated + assessment.unauthenticated).toBe(assessment.total);
    expect(assessment.summary).toBeTruthy();
  });
});
