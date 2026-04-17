import { describe, it, expect } from "vitest";
import path from "node:path";
import { IacScanner } from "../iac-scanner.js";

const DEMO_APP = path.resolve(__dirname, "../../../demo-vulnerable-app");

describe("IacScanner", () => {
  it("finds IaC misconfigurations in demo app", async () => {
    const scanner = new IacScanner();
    const result = await scanner.scan(DEMO_APP);

    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("detects Docker running as root", async () => {
    const scanner = new IacScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    const rootUser = findings.filter((f) => f.rule === "iac:docker-root-user");
    expect(rootUser.length).toBeGreaterThan(0);
    expect(rootUser[0].severity).toBe("high");
  });

  it("detects Docker latest tag", async () => {
    const scanner = new IacScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    const latest = findings.filter((f) => f.rule === "iac:docker-latest-tag");
    expect(latest.length).toBeGreaterThan(0);
  });

  it("detects secrets in Docker ENV/ARG", async () => {
    const scanner = new IacScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    const secrets = findings.filter((f) => f.rule === "iac:docker-secret-in-env");
    expect(secrets.length).toBeGreaterThanOrEqual(2); // ARG + ENV
  });

  it("detects Terraform public access 0.0.0.0/0", async () => {
    const scanner = new IacScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    const publicAccess = findings.filter((f) => f.rule === "iac:tf-public-access");
    expect(publicAccess.length).toBeGreaterThan(0);
    expect(publicAccess[0].severity).toBe("high");
  });

  it("detects Terraform hardcoded secrets", async () => {
    const scanner = new IacScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    const secrets = findings.filter((f) => f.rule === "iac:tf-hardcoded-secret");
    expect(secrets.length).toBeGreaterThan(0);
    expect(secrets[0].severity).toBe("critical");
  });

  it("assigns IAC- prefix IDs", async () => {
    const scanner = new IacScanner();
    const { findings } = await scanner.scan(DEMO_APP);

    for (const f of findings) {
      expect(f.id).toMatch(/^IAC-\d{4}$/);
      expect(f.category).toBe("iac");
    }
  });
});
