import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { Vulnerability } from "../types/index.js";

interface CacheEntry {
  hash: string;
  timestamp: string;
  findings: Vulnerability[];
}

interface CacheData {
  version: number;
  entries: Record<string, CacheEntry>;
}

const CACHE_VERSION = 1;
const CACHE_DIR = ".sphinx";
const CACHE_FILE = "scan-cache.json";

export class ScanCache {
  private data: CacheData;
  private cachePath: string;
  private dirty = false;

  constructor(projectPath: string) {
    this.cachePath = path.join(projectPath, CACHE_DIR, CACHE_FILE);
    this.data = this.load();
  }

  /**
   * Check if a file has changed since the last scan.
   * Returns cached findings if unchanged, null if the file needs scanning.
   */
  getCached(filePath: string, absPath: string): Vulnerability[] | null {
    const entry = this.data.entries[filePath];
    if (!entry) return null;

    const currentHash = this.hashFile(absPath);
    if (!currentHash) return null;

    if (entry.hash === currentHash) {
      return entry.findings;
    }

    return null;
  }

  /**
   * Store findings for a file along with its content hash.
   */
  set(filePath: string, absPath: string, findings: Vulnerability[]): void {
    const hash = this.hashFile(absPath);
    if (!hash) return;

    this.data.entries[filePath] = {
      hash,
      timestamp: new Date().toISOString(),
      findings,
    };
    this.dirty = true;
  }

  /**
   * Remove stale entries for files that no longer exist.
   */
  prune(existingFiles: Set<string>): number {
    let removed = 0;
    for (const key of Object.keys(this.data.entries)) {
      if (!existingFiles.has(key)) {
        delete this.data.entries[key];
        removed++;
        this.dirty = true;
      }
    }
    return removed;
  }

  /**
   * Save the cache to disk.
   */
  save(): void {
    if (!this.dirty) return;

    const dir = path.dirname(this.cachePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(this.cachePath, JSON.stringify(this.data, null, 2), "utf-8");
    this.dirty = false;
  }

  /**
   * Clear all cached data.
   */
  clear(): void {
    this.data = { version: CACHE_VERSION, entries: {} };
    this.dirty = true;
    this.save();
  }

  get stats(): { files: number; age: string | null } {
    const entries = Object.values(this.data.entries);
    if (entries.length === 0) return { files: 0, age: null };

    const oldest = entries.reduce((min, e) => (e.timestamp < min.timestamp ? e : min));
    return {
      files: entries.length,
      age: oldest.timestamp,
    };
  }

  private load(): CacheData {
    if (!fs.existsSync(this.cachePath)) {
      return { version: CACHE_VERSION, entries: {} };
    }

    try {
      const raw = JSON.parse(fs.readFileSync(this.cachePath, "utf-8"));
      if (raw.version !== CACHE_VERSION) {
        return { version: CACHE_VERSION, entries: {} };
      }
      return raw;
    } catch {
      return { version: CACHE_VERSION, entries: {} };
    }
  }

  private hashFile(absPath: string): string | null {
    try {
      const content = fs.readFileSync(absPath);
      return crypto.createHash("sha256").update(content).digest("hex");
    } catch {
      return null;
    }
  }
}
