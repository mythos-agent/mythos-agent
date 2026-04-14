import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { ScanCache } from "../scan-cache.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-cache-test-"));
  // Create a test file
  fs.writeFileSync(path.join(tmpDir, "test.ts"), "const x = 1;");
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("ScanCache", () => {
  it("returns null for uncached files", () => {
    const cache = new ScanCache(tmpDir);
    const result = cache.getCached("test.ts", path.join(tmpDir, "test.ts"));
    expect(result).toBeNull();
  });

  it("returns cached findings for unchanged files", () => {
    const cache = new ScanCache(tmpDir);
    const findings = [
      {
        id: "SPX-0001",
        rule: "test",
        title: "Test",
        description: "test",
        severity: "high" as const,
        category: "test",
        confidence: "high" as const,
        location: { file: "test.ts", line: 1 },
      },
    ];

    cache.set("test.ts", path.join(tmpDir, "test.ts"), findings);
    cache.save();

    // Reload cache from disk
    const cache2 = new ScanCache(tmpDir);
    const cached = cache2.getCached("test.ts", path.join(tmpDir, "test.ts"));
    expect(cached).toHaveLength(1);
    expect(cached![0].id).toBe("SPX-0001");
  });

  it("invalidates cache when file changes", () => {
    const cache = new ScanCache(tmpDir);
    cache.set("test.ts", path.join(tmpDir, "test.ts"), []);
    cache.save();

    // Modify the file
    fs.writeFileSync(path.join(tmpDir, "test.ts"), "const x = 2; // changed");

    const cache2 = new ScanCache(tmpDir);
    const cached = cache2.getCached("test.ts", path.join(tmpDir, "test.ts"));
    expect(cached).toBeNull();
  });

  it("prunes entries for deleted files", () => {
    // Create a file, cache it, then delete it
    const deletedPath = path.join(tmpDir, "deleted.ts");
    fs.writeFileSync(deletedPath, "const y = 2;");

    const cache = new ScanCache(tmpDir);
    cache.set("test.ts", path.join(tmpDir, "test.ts"), []);
    cache.set("deleted.ts", deletedPath, []);

    // Now "deleted.ts" is no longer in the existing files set
    const removed = cache.prune(new Set(["test.ts"]));
    expect(removed).toBe(1);
  });

  it("reports correct stats", () => {
    const cache = new ScanCache(tmpDir);
    expect(cache.stats.files).toBe(0);

    cache.set("test.ts", path.join(tmpDir, "test.ts"), []);
    expect(cache.stats.files).toBe(1);
  });

  it("clear removes all entries", () => {
    const cache = new ScanCache(tmpDir);
    cache.set("test.ts", path.join(tmpDir, "test.ts"), []);
    cache.clear();
    expect(cache.stats.files).toBe(0);
  });
});
