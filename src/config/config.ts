import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { DEFAULT_CONFIG, type SphinxConfig } from "../types/index.js";

const CONFIG_FILENAME = ".sphinx.yml";

export function findConfigFile(startDir: string): string | null {
  let dir = path.resolve(startDir);
  while (true) {
    const configPath = path.join(dir, CONFIG_FILENAME);
    if (fs.existsSync(configPath)) return configPath;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export function loadConfig(projectPath: string): SphinxConfig {
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

  // Environment variables override file config
  if (process.env.SPHINX_API_KEY) {
    config.apiKey = process.env.SPHINX_API_KEY;
  }
  if (process.env.ANTHROPIC_API_KEY && !config.apiKey) {
    config.apiKey = process.env.ANTHROPIC_API_KEY;
  }
  if (process.env.SPHINX_MODEL) {
    config.model = process.env.SPHINX_MODEL;
  }

  return config;
}

export function writeConfig(dir: string, config: Partial<SphinxConfig>): string {
  const configPath = path.join(dir, CONFIG_FILENAME);
  const content = yaml.dump(config, { lineWidth: 80, noRefs: true });
  fs.writeFileSync(configPath, content, "utf-8");
  return configPath;
}
