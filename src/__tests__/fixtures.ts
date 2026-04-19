import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Shared test fixture helper. Creates an isolated tempdir, writes a
 * dictionary of files into it, and registers the dir for auto-cleanup
 * via the returned `cleanup()` function.
 *
 * The conventional pattern callers use:
 *
 *   const tmpDirs: string[] = [];
 *   const make = (files?: Record<string, string>) => {
 *     const d = fixture(files, "my-test-");
 *     tmpDirs.push(d);
 *     return d;
 *   };
 *   afterEach(() => cleanupTmpDirs(tmpDirs));
 *
 * Six test files in the repo previously open-coded this pattern with
 * near-identical implementations. Centralizing here so any cross-OS
 * tweaks (e.g., EACCES retries on Windows) need one patch, not six.
 */
export function fixture(files: Record<string, string> = {}, prefix = "mythos-"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return dir;
}

/**
 * Remove every directory in `dirs`, clearing the array. Safe to call
 * in afterEach — missing dirs are ignored (force: true).
 */
export function cleanupTmpDirs(dirs: string[]): void {
  while (dirs.length) {
    const d = dirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
}
