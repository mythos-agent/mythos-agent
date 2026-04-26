import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability } from "../types/index.js";

/**
 * Detect regex patterns vulnerable to catastrophic backtracking (ReDoS).
 *
 * Vulnerable patterns typically have:
 * 1. Nested quantifiers: (a+)+ or (a*)*
 * 2. Overlapping alternatives: (a|a)+
 * 3. Greedy quantifiers with ambiguous repetition: .*.*
 */

// Patterns that extract regex source from JS/TS code. Each entry is a
// regex that captures the regex source in group 1, plus an optional
// `gate` second-pattern that must also match the captured source for
// the extraction to count — used to prune false-positive matches from
// extractors broader than `new RegExp(...)` (notably template literals).
const REGEX_EXTRACTION_PATTERNS: Array<{ pattern: RegExp; gate?: RegExp }> = [
  // new RegExp("literal") / new RegExp('literal') — also matches a
  // backtick-delimited arg when there's no ${} interpolation inside.
  { pattern: /new\s+RegExp\s*\(\s*["'`]([^"'`]+)["'`]/g },
  // /pattern/flags regex literal.
  { pattern: /\/([^/\n]{3,})\/[gimsuy]*/g },
  // Bare template literal. Regex sources also flow into `new RegExp`
  // indirectly via helper functions (e.g. semver's `createToken` wraps
  // `new RegExp(value)` where `value` is a template literal built by
  // the caller — CVE-2022-25883). We therefore extract ANY template
  // literal and gate on REGEX_SOURCE_HEURISTIC so string-interpolation
  // templates (JSX, SQL, log formatters) don't flood the scanner.
  {
    pattern: /`((?:\\`|[^`])+)`/g,
    gate: /\\[sdwbSDWB]|\[[^\]]{1,}\]|\(\?[:=!]/,
  },
];

// Patterns within regex that indicate ReDoS vulnerability. When
// `requires` is set, the indicator fires only if the regex source ALSO
// matches that secondary pattern — used to scope template-literal
// heuristics to cases where the risky construct is actually present.
const REDOS_INDICATORS: Array<{
  pattern: RegExp;
  description: string;
  requires?: RegExp;
}> = [
  // Nested quantifiers: (a+)+, (a*)+, (a+)*, etc.
  { pattern: /\([^)]*[+*]\)[+*]/, description: "Nested quantifiers" },
  { pattern: /\([^)]*[+*]\)\{/, description: "Nested quantifier with repetition" },

  // Overlapping character classes with quantifiers
  { pattern: /\.\*\.\*/, description: "Multiple greedy wildcards" },
  { pattern: /\.\+\.\+/, description: "Multiple greedy one-or-more" },

  // Repeated groups with alternatives: (a|b)*
  { pattern: /\([^)]*\|[^)]*\)[+*]/, description: "Alternation in repeated group" },

  // Back-references with quantifiers
  { pattern: /\\[1-9].*[+*]/, description: "Back-reference with quantifier" },

  // Known dangerous patterns
  { pattern: /\(\.\*\)\+/, description: "Greedy capture repeated" },
  { pattern: /\([a-z]-[a-z]\]\+\)\+/i, description: "Character class repeated in repeated group" },

  // CVE-2022-25883 (semver) class: unbounded whitespace next to a
  // template interpolation slot. The ${...} can itself match
  // whitespace at runtime, and the ambiguity with the adjacent \s*/\s+
  // produces catastrophic backtracking. Gated on ${ presence so we
  // don't flag every \s* in a regex literal.
  {
    pattern: /\\s[*+]/,
    description: "Unbounded whitespace adjacent to template interpolation",
    requires: /\$\{/,
  },
];

export interface RedosScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class RedosScanner {
  async scan(projectPath: string): Promise<RedosScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
      nodir: true,
    });

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Extract regex patterns from the line
        for (const { pattern: extractor, gate } of REGEX_EXTRACTION_PATTERNS) {
          extractor.lastIndex = 0;
          let match;
          while ((match = extractor.exec(line)) !== null) {
            const regexStr = match[1];
            if (!regexStr || regexStr.length < 3) continue;
            // Extractor-level gate: e.g., template literal must look
            // like a regex source before we consider its contents.
            if (gate && !gate.test(regexStr)) continue;

            // Check for ReDoS indicators
            for (const indicator of REDOS_INDICATORS) {
              if (
                indicator.pattern.test(regexStr) &&
                (!indicator.requires || indicator.requires.test(regexStr))
              ) {
                // Check if this regex processes user input
                const context = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
                const isUserFacing =
                  /req\.|input|user|body|query|params|request|data|search|filter|match/i.test(
                    context
                  );

                findings.push({
                  id: `REDOS-${String(idCounter++).padStart(4, "0")}`,
                  rule: "redos:vulnerable-pattern",
                  title: `ReDoS: ${indicator.description} — ${isUserFacing ? "user-facing" : "internal"}`,
                  description: `Regex pattern "${regexStr.slice(0, 60)}" is vulnerable to catastrophic backtracking (${indicator.description}). ${isUserFacing ? "This regex processes user input — an attacker can cause CPU exhaustion with a crafted string." : "Consider simplifying even for internal use."}`,
                  severity: isUserFacing ? "high" : "low",
                  category: "redos",
                  cwe: "CWE-1333",
                  confidence: isUserFacing ? "high" : "medium",
                  location: {
                    file: relativePath,
                    line: i + 1,
                    snippet: line.trim().slice(0, 120),
                  },
                });
                break; // One finding per regex
              }
            }
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
