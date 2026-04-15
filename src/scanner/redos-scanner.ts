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

// Patterns that extract regex from code
const REGEX_EXTRACTION_PATTERNS = [
  // new RegExp("pattern")
  /new\s+RegExp\s*\(\s*["'`]([^"'`]+)["'`]/g,
  // /pattern/flags
  /\/([^/\n]{3,})\/[gimsuy]*/g,
];

// Patterns within regex that indicate ReDoS vulnerability
const REDOS_INDICATORS: Array<{
  pattern: RegExp;
  description: string;
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
];

export interface RedosScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class RedosScanner {
  async scan(projectPath: string): Promise<RedosScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py"],
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
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch { continue; }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Extract regex patterns from the line
        for (const extractor of REGEX_EXTRACTION_PATTERNS) {
          extractor.lastIndex = 0;
          let match;
          while ((match = extractor.exec(line)) !== null) {
            const regexStr = match[1];
            if (!regexStr || regexStr.length < 3) continue;

            // Check for ReDoS indicators
            for (const indicator of REDOS_INDICATORS) {
              if (indicator.pattern.test(regexStr)) {
                // Check if this regex processes user input
                const context = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
                const isUserFacing = /req\.|input|user|body|query|params|request|data|search|filter|match/i.test(context);

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
