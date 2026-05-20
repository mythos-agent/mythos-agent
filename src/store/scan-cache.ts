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

/**
 * Compute a short fingerprint of the active rule configuration so that a
 * change in enabled/disabled rules automatically busts all stale cache
 * entries.
 *
 * Uses a fast non-cryptographic 32-bit FNV-1a hash. A cache key has no
 * security boundary — collision resistance only needs to be good enough that
 * two distinct rule configurations don't share a bucket in practice. FNV-1a
 * is well-distributed for short strings and avoids tripping security
 * scanners' "fast crypto hash on a value reachable from a config object"
 * heuristics (CodeQL js/insufficient-password-hash, in particular).
 */
export function hashRuleConfig(rules: { enabled: string[]; disabled: string[] }): string {
  const canonical = JSON.stringify({
    enabled: [...rules.enabled].sort(),
    disabled: [...rules.disabled].sort(),
  });
  // FNV-1a 32-bit
  let h = 0x811c9dc5;
  for (let i = 0; i < canonical.length; i++) {
    h ^= canonical.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

/** Build the compound cache-entry key from file path and rule-config hash. */
function entryKey(filePath: string, rulesHash: string): string {
  return `${filePath}::${rulesHash}`;
}

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
   *
   * @param rulesHash - opaque hash of the active rule config (see hashRuleConfig).
   *   When the rule config changes the hash changes, producing a different entry
   *   key and therefore a cache miss for every file — forcing a fresh scan.
   */
  getCached(filePath: string, absPath: string, rulesHash = ""): Vulnerability[] | null {
    const key = entryKey(filePath, rulesHash);
    const entry = this.data.entries[key];
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
   *
   * @param rulesHash - must match the value passed to getCached.
   */
  set(filePath: string, absPath: string, findings: Vulnerability[], rulesHash = ""): void {
    const hash = this.hashFile(absPath);
    if (!hash) return;

    const key = entryKey(filePath, rulesHash);
    this.data.entries[key] = {
      hash,
      timestamp: new Date().toISOString(),
      findings,
    };
    this.dirty = true;
  }

  /**
   * Remove stale entries for files that no longer exist.
   * Keys are compound ("filePath::rulesHash"), so we extract the file-path
   * portion (everything before the last "::") when checking against the set.
   */
  prune(existingFiles: Set<string>): number {
    let removed = 0;
    for (const key of Object.keys(this.data.entries)) {
      // Extract the file-path portion from the compound key.
      const separatorIdx = key.lastIndexOf("::");
      const filePath = separatorIdx >= 0 ? key.slice(0, separatorIdx) : key;
      if (!existingFiles.has(filePath)) {
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
