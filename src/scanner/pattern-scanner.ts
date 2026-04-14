import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type {
  SphinxConfig,
  Vulnerability,
  RuleDefinition,
  Severity,
} from "../types/index.js";
import { loadBuiltinRules } from "../rules/builtin-rules.js";
import { loadFrameworkRules } from "../rules/framework-rules.js";
import { loadCustomRules } from "../rules/custom-rules.js";
import { ScanCache } from "../store/scan-cache.js";

interface ScanOutput {
  findings: Vulnerability[];
  filesScanned: number;
  languages: string[];
  cacheHits: number;
}

const LANG_MAP: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".py": "python",
  ".rb": "ruby",
  ".go": "go",
  ".java": "java",
  ".php": "php",
};

export class PatternScanner {
  private rules: RuleDefinition[];

  constructor(private config: SphinxConfig, customRulesPath?: string) {
    this.rules = [
      ...loadBuiltinRules(),
      ...loadFrameworkRules(),
      ...loadCustomRules(customRulesPath),
    ];
  }

  async scan(
    projectPath: string,
    useCache = true
  ): Promise<ScanOutput> {
    const files = await this.discoverFiles(projectPath);
    const languages = new Set<string>();
    const findings: Vulnerability[] = [];
    let idCounter = 1;
    let cacheHits = 0;

    const cache = useCache ? new ScanCache(projectPath) : null;

    for (const file of files) {
      const ext = path.extname(file);
      const lang = LANG_MAP[ext];
      if (lang) languages.add(lang);

      const relativePath = path.relative(projectPath, file);

      // Check cache
      if (cache) {
        const cached = cache.getCached(relativePath, file);
        if (cached) {
          findings.push(...cached);
          cacheHits++;
          continue;
        }
      }

      const content = fs.readFileSync(file, "utf-8");
      const lines = content.split("\n");
      const fileFindings: Vulnerability[] = [];

      for (const rule of this.rules) {
        if (lang && !rule.languages.includes(lang) && !rule.languages.includes("*"))
          continue;

        for (const rulePattern of rule.patterns) {
          if (rulePattern.type === "regex") {
            const regex = new RegExp(rulePattern.pattern, "gi");
            for (let i = 0; i < lines.length; i++) {
              regex.lastIndex = 0;
              if (regex.test(lines[i])) {
                fileFindings.push({
                  id: `SPX-${String(idCounter++).padStart(4, "0")}`,
                  rule: rule.id,
                  title: rule.title,
                  description: rule.description,
                  severity: rule.severity,
                  category: rule.category,
                  cwe: rule.cwe,
                  confidence: "medium",
                  location: {
                    file: relativePath,
                    line: i + 1,
                    snippet: lines[i].trim(),
                  },
                });
              }
            }
          }
        }
      }

      // Cache the per-file findings
      if (cache) {
        cache.set(relativePath, file, fileFindings);
      }
      findings.push(...fileFindings);
    }

    // Save cache and prune stale entries
    if (cache) {
      const existingFiles = new Set(
        files.map((f) => path.relative(projectPath, f))
      );
      cache.prune(existingFiles);
      cache.save();
    }

    return {
      findings,
      filesScanned: files.length,
      languages: [...languages],
      cacheHits,
    };
  }

  private async discoverFiles(projectPath: string): Promise<string[]> {
    const files = await glob(this.config.scan.include, {
      cwd: projectPath,
      absolute: true,
      ignore: this.config.scan.exclude,
      nodir: true,
    });

    return files.filter((f) => {
      try {
        const stats = fs.statSync(f);
        return stats.size <= this.config.scan.maxFileSize;
      } catch {
        return false;
      }
    });
  }
}
