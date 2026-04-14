import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import yaml from "js-yaml";
import type { RuleDefinition } from "../types/index.js";

interface YamlRule {
  id: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  cwe?: string;
  languages: string[];
  patterns: Array<{
    type?: string;
    pattern: string;
    message?: string;
  }>;
}

export function loadCustomRules(
  rulesPath?: string,
  projectPath?: string
): RuleDefinition[] {
  const base = projectPath || process.cwd();
  const searchPaths = [
    rulesPath,
    path.join(base, ".sphinx/rules"),
    path.join(base, ".sphinx/rules.yml"),
  ].filter(Boolean) as string[];

  const rules: RuleDefinition[] = [];

  for (const searchPath of searchPaths) {
    if (!fs.existsSync(searchPath)) continue;

    const stat = fs.statSync(searchPath);

    if (stat.isDirectory()) {
      const files = glob.sync("**/*.{yml,yaml}", { cwd: searchPath, absolute: true });
      for (const file of files) {
        rules.push(...parseRuleFile(file));
      }
    } else if (stat.isFile()) {
      rules.push(...parseRuleFile(searchPath));
    }
  }

  return rules;
}

function parseRuleFile(filePath: string): RuleDefinition[] {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    const data = yaml.load(content);

    if (Array.isArray(data)) {
      return data.map(normalizeRule).filter(Boolean) as RuleDefinition[];
    }

    if (data && typeof data === "object" && "rules" in data) {
      const doc = data as { rules: YamlRule[] };
      return doc.rules.map(normalizeRule).filter(Boolean) as RuleDefinition[];
    }

    const single = normalizeRule(data as YamlRule);
    return single ? [single] : [];
  } catch {
    return [];
  }
}

function normalizeRule(raw: YamlRule): RuleDefinition | null {
  if (!raw || !raw.id || !raw.patterns || !Array.isArray(raw.patterns)) {
    return null;
  }

  return {
    id: raw.id,
    title: raw.title || raw.id,
    description: raw.description || "",
    severity: (raw.severity as RuleDefinition["severity"]) || "medium",
    category: raw.category || "custom",
    cwe: raw.cwe,
    languages: raw.languages || ["*"],
    patterns: raw.patterns.map((p) => ({
      type: (p.type as "regex" | "ast") || "regex",
      pattern: p.pattern,
      message: p.message,
    })),
  };
}
