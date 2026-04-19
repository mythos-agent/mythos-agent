import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { DEFAULT_CONFIG, type MythosConfig } from "../types/index.js";

// Preferred config filename is .mythos.yml; .sphinx.yml is accepted for
// back-compat with projects created during the sphinx-branded era through
// 3.x. When both exist in the same directory, .mythos.yml wins — that's
// the migration path: copy sphinx → mythos, next run picks up the new file.
// 4.0 drops .sphinx.yml support entirely.
const CANONICAL_CONFIG_FILENAME = ".mythos.yml";
const LEGACY_CONFIG_FILENAME = ".sphinx.yml";

export function findConfigFile(startDir: string): string | null {
  let dir = path.resolve(startDir);
  while (true) {
    const canonical = path.join(dir, CANONICAL_CONFIG_FILENAME);
    if (fs.existsSync(canonical)) return canonical;
    const legacy = path.join(dir, LEGACY_CONFIG_FILENAME);
    if (fs.existsSync(legacy)) return legacy;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export function loadConfig(projectPath: string): MythosConfig {
  const config = structuredClone(DEFAULT_CONFIG);

  // Load from file — deep merge to preserve nested defaults
  const configFile = findConfigFile(projectPath);
  if (configFile) {
    const raw = fs.readFileSync(configFile, "utf-8");
    const fileConfig = yaml.load(raw) as Record<string, unknown>;
    if (fileConfig) {
      if (fileConfig.apiKey) config.apiKey = fileConfig.apiKey as string;
      if (fileConfig.model) config.model = fileConfig.model as string;
      if (fileConfig.provider) config.provider = fileConfig.provider as string;
      if (fileConfig.rules && typeof fileConfig.rules === "object") {
        Object.assign(config.rules, fileConfig.rules);
      }
      if (fileConfig.scan && typeof fileConfig.scan === "object") {
        Object.assign(config.scan, fileConfig.scan);
      }
    }
  }

  // Environment variables override file config.
  // MYTHOS_* is preferred; SPHINX_* is accepted for back-compat through 3.x.
  // When both are set, MYTHOS_* wins. ANTHROPIC_API_KEY is the standard
  // upstream fallback and applies only when neither of the others is set.
  const envApiKey = process.env.MYTHOS_API_KEY || process.env.SPHINX_API_KEY;
  if (envApiKey) config.apiKey = envApiKey;
  if (process.env.ANTHROPIC_API_KEY && !config.apiKey) {
    config.apiKey = process.env.ANTHROPIC_API_KEY;
  }
  const envModel = process.env.MYTHOS_MODEL || process.env.SPHINX_MODEL;
  if (envModel) config.model = envModel;

  return config;
}

export function writeConfig(dir: string, config: Partial<MythosConfig>): string {
  // New configs always land in .mythos.yml; an existing .sphinx.yml in the
  // same directory is left untouched so we don't surprise users, but the
  // next findConfigFile() call will prefer the newly-written .mythos.yml.
  const configPath = path.join(dir, CANONICAL_CONFIG_FILENAME);
  const content = yaml.dump(config, { lineWidth: 80, noRefs: true });
  fs.writeFileSync(configPath, content, "utf-8");
  return configPath;
}
