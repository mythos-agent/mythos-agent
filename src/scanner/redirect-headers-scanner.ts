import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability } from "../types/index.js";

/**
 * Detect incomplete header stripping on cross-host HTTP redirects —
 * the CVE-2024-28849 (follow-redirects) class.
 *
 * The buggy shape: a redirect handler drops `authorization` and
 * `cookie` headers when following a cross-host redirect but does NOT
 * also drop `proxy-authorization` (or other auth-bearing headers).
 * That leaks proxy credentials to the new host. The exact upstream
 * fix in CVE-2024-28849 added `proxy-authorization` to the strip
 * regex; the deterministic fingerprint we look for is the absence of
 * that addition.
 *
 * Detection is two heuristics in sequence (kept simple deliberately —
 * a deeper taint analysis would over-trigger on benign middleware):
 *  1. A regex literal in the file source matches `authorization`
 *     case-insensitively but does NOT also match `proxy.authorization`.
 *  2. Within ±5 lines of that regex, the file mentions
 *     `redirect`, `.location`, `Location:`, or `followRedirects` —
 *     i.e. the regex is plausibly used in redirect handling.
 *
 * Both gates must fire for a finding. The ±5-line window mirrors
 * RedosScanner's user-input proximity heuristic; tuning either bound
 * trades recall for precision.
 */

const AUTHORIZATION_PATTERN = /authorization/i;
// Catches the patched form regardless of the exact regex syntax used to
// add proxy support. The CVE-2024-28849 fix used `(?:proxy-)?authorization`
// with three characters between "proxy" and "authorization" — too many
// for an adjacency-style regex to match. The presence of both "proxy"
// and "authorization" in the regex source is the signal we want.
const PROXY_PRESENCE_PATTERN = /proxy/i;
const REDIRECT_CONTEXT = /\bredirect|\.location\b|Location:|followRedirects/i;

// Matches /pattern/flags — same shape as RedosScanner's literal extractor.
// We don't need new RegExp(...) coverage here because the exploitable
// pattern in CVE-2024-28849 was a literal regex passed to a helper.
const REGEX_LITERAL = /\/((?:\\.|[^/\n\\])+)\/[gimsuy]*/g;

export interface RedirectHeadersScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class RedirectHeadersScanner {
  async scan(projectPath: string): Promise<RedirectHeadersScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"],
      {
        cwd: projectPath,
        absolute: true,
        ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
        nodir: true,
      }
    );

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      // Open the file once, fstat the descriptor, then read from the
      // same handle so the size check and the read agree on the same
      // file content (avoids the TOCTOU pattern CodeQL js/file-system-race
      // flags on stat → read sequences against named paths).
      let fd: number | null = null;
      try {
        fd = fs.openSync(file, "r");
        const stats = fs.fstatSync(fd);
        if (stats.size > 500_000) continue;
        const buf = Buffer.alloc(stats.size);
        fs.readSync(fd, buf, 0, stats.size, 0);
        content = buf.toString("utf-8");
      } catch {
        continue;
      } finally {
        if (fd !== null) {
          try {
            fs.closeSync(fd);
          } catch {
            // ignore: descriptor may already be closed if openSync failed
          }
        }
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        REGEX_LITERAL.lastIndex = 0;
        let match;
        while ((match = REGEX_LITERAL.exec(line)) !== null) {
          const regexSrc = match[1];
          if (!regexSrc) continue;
          if (!AUTHORIZATION_PATTERN.test(regexSrc)) continue;
          // If the regex already mentions "proxy" anywhere, treat it as
          // covering proxy-authorization. False-negative risk is low —
          // any regex listing "proxy" in a redirect-handling context is
          // doing the right thing or close to it.
          if (PROXY_PRESENCE_PATTERN.test(regexSrc)) continue;

          // Context check: regex must plausibly be used in redirect
          // handling, not (e.g.) a generic auth-header validator.
          const contextStart = Math.max(0, i - 5);
          const contextEnd = Math.min(lines.length, i + 6);
          const context = lines.slice(contextStart, contextEnd).join("\n");
          if (!REDIRECT_CONTEXT.test(context)) continue;

          findings.push({
            id: `RHDR-${String(idCounter++).padStart(4, "0")}`,
            rule: "credential:incomplete-redirect-header-strip",
            title: "Incomplete header strip on cross-host redirect (proxy-authorization preserved)",
            description: `Regex /${regexSrc}/ removes some auth-bearing headers (authorization/cookie) on redirect but does not list proxy-authorization. A redirect to a third-party host can therefore leak proxy credentials. CVE-2024-28849 (follow-redirects) was this exact pattern; the upstream fix added proxy-authorization to the strip regex.`,
            severity: "medium",
            category: "credential-leak",
            cwe: "CWE-200",
            confidence: "high",
            location: {
              file: relativePath,
              line: i + 1,
              snippet: line.trim().slice(0, 160),
            },
          });
          break; // one finding per regex literal
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
