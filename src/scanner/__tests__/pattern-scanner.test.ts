import { describe, it, expect } from "vitest";
import path from "node:path";
import { PatternScanner } from "../pattern-scanner.js";
import { DEFAULT_CONFIG } from "../../types/index.js";

const DEMO_APP = path.resolve(__dirname, "../../../demo-vulnerable-app");

function makeConfig(overrides = {}) {
  return { ...structuredClone(DEFAULT_CONFIG), ...overrides };
}

describe("PatternScanner", () => {
  it("finds vulnerabilities in demo app", async () => {
    const scanner = new PatternScanner(makeConfig());
    const result = await scanner.scan(DEMO_APP, false);

    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.languages).toContain("typescript");
  });

  it("detects SQL injection", async () => {
    const scanner = new PatternScanner(makeConfig());
    const { findings } = await scanner.scan(DEMO_APP, false);

    const sqli = findings.filter((f) => f.rule === "sql-injection");
    expect(sqli.length).toBeGreaterThan(0);
    expect(sqli[0].severity).toBe("critical");
    expect(sqli[0].cwe).toBe("CWE-89");
  });

  it("detects XSS via dangerouslySetInnerHTML", async () => {
    const scanner = new PatternScanner(makeConfig());
    const { findings } = await scanner.scan(DEMO_APP, false);

    const xss = findings.filter((f) => f.rule === "xss-unescaped");
    expect(xss.length).toBeGreaterThan(0);
    expect(xss[0].severity).toBe("high");
  });

  it("detects eval() usage", async () => {
    const scanner = new PatternScanner(makeConfig());
    const { findings } = await scanner.scan(DEMO_APP, false);

    const evalFindings = findings.filter((f) => f.rule === "eval-usage");
    expect(evalFindings.length).toBeGreaterThan(0);
  });

  it("detects hardcoded secrets", async () => {
    const scanner = new PatternScanner(makeConfig());
    const { findings } = await scanner.scan(DEMO_APP, false);

    const secrets = findings.filter((f) => f.rule === "hardcoded-secret");
    expect(secrets.length).toBeGreaterThan(0);
    expect(secrets[0].cwe).toBe("CWE-798");
  });

  it("detects JWT decode without verify", async () => {
    const scanner = new PatternScanner(makeConfig());
    const { findings } = await scanner.scan(DEMO_APP, false);

    const jwt = findings.filter((f) => f.rule === "jwt-none-alg");
    expect(jwt.length).toBeGreaterThan(0);
    expect(jwt[0].severity).toBe("critical");
  });

  it("assigns unique IDs with SPX- prefix", async () => {
    const scanner = new PatternScanner(makeConfig());
    const { findings } = await scanner.scan(DEMO_APP, false);

    const ids = findings.map((f) => f.id);
    expect(ids[0]).toMatch(/^SPX-\d{4}$/);
    expect(new Set(ids).size).toBe(ids.length); // all unique
  });

  it("includes file location with line numbers", async () => {
    const scanner = new PatternScanner(makeConfig());
    const { findings } = await scanner.scan(DEMO_APP, false);

    for (const f of findings) {
      expect(f.location.file).toBeTruthy();
      expect(f.location.line).toBeGreaterThan(0);
    }
  });

  it("respects exclude patterns", async () => {
    const config = makeConfig({
      scan: {
        ...DEFAULT_CONFIG.scan,
        exclude: ["**/*"],
      },
    });
    const scanner = new PatternScanner(config);
    const result = await scanner.scan(DEMO_APP, false);

    expect(result.filesScanned).toBe(0);
    expect(result.findings.length).toBe(0);
  });

  it("uses cache on second scan", async () => {
    const scanner = new PatternScanner(makeConfig());
    const first = await scanner.scan(DEMO_APP, true);
    const second = await scanner.scan(DEMO_APP, true);

    expect(second.findings.length).toBe(first.findings.length);
    expect(second.cacheHits).toBeGreaterThan(0);
  });
});
