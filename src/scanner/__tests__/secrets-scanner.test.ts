import { describe, it, expect } from "vitest";
import path from "node:path";
import { SecretsScanner } from "../secrets-scanner.js";

const DEMO_APP = path.resolve(__dirname, "../../../demo-vulnerable-app");

describe("SecretsScanner", () => {
  it("finds secrets in demo app", async () => {
    const scanner = new SecretsScanner();
    const result = await scanner.scan(DEMO_APP);

    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("detects database connection strings", async () => {
    const scanner = new SecretsScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    const dbUrls = findings.filter((f) => f.rule === "secret:database-url");
    expect(dbUrls.length).toBeGreaterThan(0);
    expect(dbUrls[0].severity).toBe("critical");
  });

  it("detects generic API key assignments", async () => {
    const scanner = new SecretsScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    const apiKeys = findings.filter((f) => f.rule === "secret:generic-api-key");
    expect(apiKeys.length).toBeGreaterThan(0);
  });

  it("masks secrets in snippets", async () => {
    const scanner = new SecretsScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    for (const f of findings) {
      if (f.location.snippet) {
        // Snippets should be masked — not contain full secret values
        expect(f.location.snippet).toMatch(/\.\.\.|masked|\*\*\*/);
      }
    }
  });

  it("assigns SECRET- prefix IDs", async () => {
    const scanner = new SecretsScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    for (const f of findings) {
      expect(f.id).toMatch(/^SECRET-\d{4}$/);
    }
  });

  it("categorizes all findings as secrets", async () => {
    const scanner = new SecretsScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    for (const f of findings) {
      expect(f.category).toBe("secrets");
      expect(f.cwe).toBe("CWE-798");
    }
  });
});
