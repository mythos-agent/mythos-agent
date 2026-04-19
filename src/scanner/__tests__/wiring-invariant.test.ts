import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { glob } from "glob";

/**
 * Invariant: every `export class NameScanner` in src/scanner/ must be
 * instantiated (`new NameScanner(...)`) somewhere in src/ outside the
 * scanner file itself and outside __tests__/. This catches scanners
 * that ship to the tarball and show up in docs/README but are not
 * reachable from any runtime entry point (CLI / HTTP API / MCP server
 * / orchestrator).
 *
 * When a scanner is deliberately experimental / staged, add its class
 * name to `KNOWN_EXPERIMENTAL` below with a one-line reason. The
 * allowlist is the documentation — if you touch it, keep the reason
 * accurate.
 */

// Scanners that are implemented + tested + advertised but not yet wired
// into a runtime entry point (CLI `scan`, HTTP API, MCP server,
// orchestrator agents). Remove from this list when wiring is added.
// Adding to this list requires a reason so future maintainers
// understand the deferral.
//
// This allowlist also IS the public record of capability drift: the
// README advertises "49 scanners" but only 9 run on a real invocation
// today. Shrinking this list is the path to closing that gap.
const KNOWN_EXPERIMENTAL = new Set<string>([
  // Application-layer deep scanners — not wired; subset that overlap
  // with the existing PatternScanner's rules.
  "SqlInjectionScanner",
  "XssDeepScanner",
  "NosqlScanner",
  "CommandInjectionScanner",
  "DeserializationScanner",
  "PathScanner",
  "OpenRedirectScanner",
  "SstiScanner",
  "XxeScanner",
  "InputValidationScanner",

  // Web / HTTP layer — not wired; overlap with HeadersScanner territory.
  "CorsScanner",
  "ClickjackingScanner",
  "OauthScanner",

  // Protocol / transport — not wired.
  "WebsocketScanner",
  "GraphqlScanner",

  // Operational / hygiene — not wired; overlap with SecretsScanner.
  "EnvScanner",
  "LoggingScanner",
  "ErrorHandlingScanner",
  "CacheScanner",
  "EmailScanner",
  "UploadScanner",

  // Supply-chain — partially overlaps DepScanner which is wired.
  "SupplyChainScanner",
  "DepConfusionScanner",

  // Recon-leaning; belongs in agents/recon-agent when wired.
  "SubdomainScanner",
  "DnsRebindingScanner",

  // Specialized analyses — not wired.
  "PermissionScanner",
  "RaceConditionScanner",
  "RedosScanner",
  "MemorySafetyScanner",
  "ZeroTrustScanner",
]);

const __filename = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(__filename), "..", "..", "..");

describe("scanner wiring invariant", () => {
  it("every scanner class is either wired into a runtime surface or explicitly experimental", async () => {
    // 1. Discover all `export class XxxScanner` declarations in src/scanner/
    const scannerFiles = await glob("src/scanner/*.ts", {
      cwd: repoRoot,
      absolute: true,
    });

    const declared = new Map<string, string>(); // className -> relative file path
    for (const file of scannerFiles) {
      const content = fs.readFileSync(file, "utf-8");
      const re = /^export class ([A-Z][A-Za-z0-9_]*Scanner)\b/gm;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) {
        declared.set(m[1], path.relative(repoRoot, file).replace(/\\/g, "/"));
      }
    }

    expect(declared.size).toBeGreaterThan(0);

    // 2. Find all `new NameScanner(` call sites in src/ outside of:
    //    - the scanner's own declaration file
    //    - any __tests__ directory
    const allSrcFiles = await glob("src/**/*.ts", {
      cwd: repoRoot,
      absolute: true,
      ignore: ["**/__tests__/**"],
    });

    const instantiated = new Set<string>();
    for (const file of allSrcFiles) {
      const content = fs.readFileSync(file, "utf-8");
      for (const className of declared.keys()) {
        if (instantiated.has(className)) continue;
        // Skip the class's own declaration file — a declaration file
        // may legitimately not instantiate itself.
        if (file.endsWith(declared.get(className)!.replace(/\//g, path.sep))) continue;
        const re = new RegExp(`\\bnew\\s+${className}\\s*\\(`);
        if (re.test(content)) instantiated.add(className);
      }
    }

    // 3. Classify: wired (OK) vs experimental (allow-listed OK) vs unwired-unexpected (fail).
    const unwiredUnexpected: string[] = [];
    for (const className of declared.keys()) {
      if (instantiated.has(className)) continue;
      if (KNOWN_EXPERIMENTAL.has(className)) continue;
      unwiredUnexpected.push(className);
    }

    if (unwiredUnexpected.length > 0) {
      const hint = unwiredUnexpected
        .map((c) => `  - ${c} (declared in ${declared.get(c)})`)
        .join("\n");
      throw new Error(
        `New scanner class(es) are not wired into any runtime surface and not in the experimental allowlist:\n${hint}\n\n` +
          "Either:\n" +
          "  (a) import + `new ${Name}Scanner()` it from a runtime entry point (cli/commands/*, server/api.ts, mcp/server.ts, agents/*, scanner/parallel-runner.ts), or\n" +
          `  (b) add it to KNOWN_EXPERIMENTAL in ${path.relative(repoRoot, __filename).replace(/\\/g, "/")} with a reason.`
      );
    }

    expect(unwiredUnexpected).toEqual([]);
  });

  it("allowlist entries are actually declared (no stale entries)", async () => {
    const scannerFiles = await glob("src/scanner/*.ts", {
      cwd: repoRoot,
      absolute: true,
    });
    const declared = new Set<string>();
    for (const file of scannerFiles) {
      const content = fs.readFileSync(file, "utf-8");
      const re = /^export class ([A-Z][A-Za-z0-9_]*Scanner)\b/gm;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) declared.add(m[1]);
    }

    const stale = Array.from(KNOWN_EXPERIMENTAL).filter((c) => !declared.has(c));
    expect(stale, "Remove these from KNOWN_EXPERIMENTAL — the classes no longer exist").toEqual([]);
  });

  it("allowlist entries are actually unwired (no false allowlisting)", async () => {
    const scannerFiles = await glob("src/scanner/*.ts", {
      cwd: repoRoot,
      absolute: true,
    });
    const declared = new Map<string, string>();
    for (const file of scannerFiles) {
      const content = fs.readFileSync(file, "utf-8");
      const re = /^export class ([A-Z][A-Za-z0-9_]*Scanner)\b/gm;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) {
        declared.set(m[1], path.relative(repoRoot, file).replace(/\\/g, "/"));
      }
    }

    const allSrcFiles = await glob("src/**/*.ts", {
      cwd: repoRoot,
      absolute: true,
      ignore: ["**/__tests__/**"],
    });
    const instantiated = new Set<string>();
    for (const file of allSrcFiles) {
      const content = fs.readFileSync(file, "utf-8");
      for (const className of declared.keys()) {
        if (instantiated.has(className)) continue;
        if (file.endsWith(declared.get(className)!.replace(/\//g, path.sep))) continue;
        const re = new RegExp(`\\bnew\\s+${className}\\s*\\(`);
        if (re.test(content)) instantiated.add(className);
      }
    }

    const wrongly = Array.from(KNOWN_EXPERIMENTAL).filter((c) => instantiated.has(c));
    expect(
      wrongly,
      "These are allowlisted as experimental but actually wired — remove from KNOWN_EXPERIMENTAL"
    ).toEqual([]);
  });
});
