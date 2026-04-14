import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { DEFAULT_CONFIG, type MythohConfig } from "../types/index.js";

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

export function loadConfig(projectPath: string): MythohConfig {
  const config = structuredClone(DEFAULT_CONFIG);

  // Load from file
  const configFile = findConfigFile(projectPath);
  if (configFile) {
    const raw = fs.readFileSync(configFile, "utf-8");
    const fileConfig = yaml.load(raw) as Partial<MythohConfig>;
    Object.assign(config, fileConfig);
  }

  // Environment variables override file config
  if (process.env.MYTHOH_API_KEY) {
    config.apiKey = process.env.MYTHOH_API_KEY;
  }
  if (process.env.ANTHROPIC_API_KEY && !config.apiKey) {
    config.apiKey = process.env.ANTHROPIC_API_KEY;
  }
  if (process.env.MYTHOH_MODEL) {
    config.model = process.env.MYTHOH_MODEL;
  }

  return config;
}

export function writeConfig(
  dir: string,
  config: Partial<MythohConfig>
): string {
  const configPath = path.join(dir, CONFIG_FILENAME);
  const content = yaml.dump(config, { lineWidth: 80, noRefs: true });
  fs.writeFileSync(configPath, content, "utf-8");
  return configPath;
}
