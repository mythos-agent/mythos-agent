import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  searchRulePacks,
  installRulePack,
  listInstalledPacks,
  uninstallRulePack,
  initRulePack,
} from "../registry.js";

// registry.ts has five exports. Two of them (searchRulePacks, installRulePack
// successful-install path) require live network calls to the npm registry +
// a working tar on PATH, so they're exercised only via their input-validation
// short-circuits here. The other three (listInstalledPacks, uninstallRulePack,
// initRulePack) are pure filesystem operations and are fully covered.

const tmpDirs: string[] = [];

function tempProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-registry-"));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

describe("searchRulePacks — input validation short-circuit", () => {
  it("returns [] when the query contains characters outside SAFE_NAME_PATTERN (no network call)", async () => {
    // Spaces aren't allowed by /^[a-z0-9@._\/-]+$/. The function must
    // short-circuit before spawnSync so `npm search "with space"` is
    // never invoked — protects against command-injection if the regex
    // ever regresses AND spawnSync is swapped for exec.
    const result = await searchRulePacks("query with spaces");
    expect(result).toEqual([]);
  });

  it("returns [] when the query contains uppercase (pattern is lowercase-only)", async () => {
    const result = await searchRulePacks("UPPERCASE-NOT-ALLOWED");
    expect(result).toEqual([]);
  });
});

describe("installRulePack — input validation short-circuit", () => {
  it("throws 'Invalid package name' for unsafe characters before any npm/tar spawn", async () => {
    const project = tempProject();
    // Assertion double: throws synchronously in the promise, no temp files
    // land on disk from the partially-progressed install.
    await expect(installRulePack("has spaces", project)).rejects.toThrow(/Invalid package name/);
  });
});

describe("listInstalledPacks — filesystem reads", () => {
  it("returns [] when no .installed.json exists (fresh project)", () => {
    const project = tempProject();
    expect(listInstalledPacks(project)).toEqual([]);
  });

  it("returns parsed entries when .installed.json is present and valid", () => {
    const project = tempProject();
    const rulesDir = path.join(project, ".mythos", "rules");
    fs.mkdirSync(rulesDir, { recursive: true });
    const entries = [
      { name: "owasp-top10", package: "mythos-agent-rules-owasp-top10" },
      { name: "custom", package: "mythos-agent-rules-custom" },
    ];
    fs.writeFileSync(path.join(rulesDir, ".installed.json"), JSON.stringify(entries));

    expect(listInstalledPacks(project)).toEqual(entries);
  });

  it("returns [] when .installed.json is malformed JSON (not a throw)", () => {
    // Silent recovery matters here: the CLI `rules list` command calls
    // this on every invocation, and a syntax error in the track file
    // shouldn't crash an unrelated command.
    const project = tempProject();
    const rulesDir = path.join(project, ".mythos", "rules");
    fs.mkdirSync(rulesDir, { recursive: true });
    fs.writeFileSync(path.join(rulesDir, ".installed.json"), "{ not json");

    expect(listInstalledPacks(project)).toEqual([]);
  });
});

describe("uninstallRulePack — filesystem mutations", () => {
  it("returns 0 when the rules directory doesn't exist (no-op, not a throw)", () => {
    const project = tempProject();
    expect(uninstallRulePack("anything", project)).toBe(0);
  });

  it("removes every <name>-*.yml and updates .installed.json to drop the entry", () => {
    const project = tempProject();
    const rulesDir = path.join(project, ".mythos", "rules");
    fs.mkdirSync(rulesDir, { recursive: true });

    // Plant two files belonging to the pack + one unrelated file that
    // must NOT be removed.
    fs.writeFileSync(path.join(rulesDir, "custom-a.yml"), "");
    fs.writeFileSync(path.join(rulesDir, "custom-b.yml"), "");
    fs.writeFileSync(path.join(rulesDir, "other-c.yml"), "");
    fs.writeFileSync(
      path.join(rulesDir, ".installed.json"),
      JSON.stringify([
        { name: "custom", package: "mythos-agent-rules-custom" },
        { name: "other", package: "mythos-agent-rules-other" },
      ])
    );

    const removed = uninstallRulePack("custom", project);

    expect(removed).toBe(2);
    expect(fs.existsSync(path.join(rulesDir, "custom-a.yml"))).toBe(false);
    expect(fs.existsSync(path.join(rulesDir, "custom-b.yml"))).toBe(false);
    expect(fs.existsSync(path.join(rulesDir, "other-c.yml"))).toBe(true); // untouched

    const installed = JSON.parse(
      fs.readFileSync(path.join(rulesDir, ".installed.json"), "utf-8")
    ) as Array<{ name: string }>;
    expect(installed.map((p) => p.name)).toEqual(["other"]);
  });

  it("skips files that don't end in .yml even if they share the name prefix", () => {
    const project = tempProject();
    const rulesDir = path.join(project, ".mythos", "rules");
    fs.mkdirSync(rulesDir, { recursive: true });
    // A stray `.json` or `.txt` with the same prefix must NOT be deleted
    // — the prefix match is only safe when combined with the .yml gate,
    // and this test protects that combination.
    fs.writeFileSync(path.join(rulesDir, "custom-readme.txt"), "");
    fs.writeFileSync(path.join(rulesDir, "custom-config.json"), "");
    fs.writeFileSync(path.join(rulesDir, "custom-rule.yml"), "");

    const removed = uninstallRulePack("custom", project);

    expect(removed).toBe(1);
    expect(fs.existsSync(path.join(rulesDir, "custom-readme.txt"))).toBe(true);
    expect(fs.existsSync(path.join(rulesDir, "custom-config.json"))).toBe(true);
    expect(fs.existsSync(path.join(rulesDir, "custom-rule.yml"))).toBe(false);
  });
});

describe("initRulePack — scaffold generation", () => {
  it("creates a package directory prefixed with mythos-agent-rules- and returns its path", () => {
    const outputDir = tempProject();
    const result = initRulePack("owasp-top10", outputDir);
    // Returned path points at the created directory, which lives inside
    // outputDir with the full REGISTRY_PREFIX-prefixed name.
    expect(result).toBe(path.join(outputDir, "mythos-agent-rules-owasp-top10"));
    expect(fs.existsSync(result)).toBe(true);
    expect(fs.statSync(result).isDirectory()).toBe(true);
  });

  it("emits package.json with the REGISTRY_PREFIX-prefixed name and the expected scaffold fields", () => {
    const outputDir = tempProject();
    const packageDir = initRulePack("my-pack", outputDir);
    const pkg = JSON.parse(fs.readFileSync(path.join(packageDir, "package.json"), "utf-8"));
    expect(pkg).toMatchObject({
      name: "mythos-agent-rules-my-pack",
      version: "1.0.0",
      main: "rules.yml",
      files: ["*.yml"],
      license: "MIT",
    });
    // keywords must include the project + the pack name so consumers
    // can find the pack via `npm search mythos-agent`.
    expect(pkg.keywords).toContain("mythos-agent");
    expect(pkg.keywords).toContain("my-pack");
  });

  it("emits rules.yml with a valid starter rule shape", () => {
    const outputDir = tempProject();
    const packageDir = initRulePack("my-pack", outputDir);
    const rulesYml = fs.readFileSync(path.join(packageDir, "rules.yml"), "utf-8");
    // The scaffold carries a starter rule so consumers have a working
    // example to edit. Assert the shape they'll see.
    expect(rulesYml).toContain("rules:");
    expect(rulesYml).toContain("id: my-pack-eval-usage");
    expect(rulesYml).toContain("severity:");
    expect(rulesYml).toContain("patterns:");
  });

  it("emits a README.md documenting install + publish workflow", () => {
    const outputDir = tempProject();
    const packageDir = initRulePack("docs-test", outputDir);
    const readme = fs.readFileSync(path.join(packageDir, "README.md"), "utf-8");
    expect(readme).toContain("mythos-agent rules install docs-test");
    expect(readme).toContain("npm publish");
  });
});
