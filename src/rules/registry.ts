import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const REGISTRY_PREFIX = "sphinx-rules-";
const SAFE_NAME_PATTERN = /^[a-z0-9@._\/-]+$/;
const LOCAL_RULES_DIR = ".sphinx/rules";

export interface RulePack {
  name: string;
  version: string;
  description: string;
  rules: number;
  author?: string;
}

export async function searchRulePacks(
  query: string
): Promise<RulePack[]> {
  const searchTerm = query
    ? `${REGISTRY_PREFIX}${query}`
    : REGISTRY_PREFIX;

  if (!SAFE_NAME_PATTERN.test(searchTerm)) {
    return [];
  }

  try {
    const result = spawnSync(
      "npm",
      ["search", searchTerm, "--json", "--long"],
      { encoding: "utf-8", timeout: 15000 }
    );
    const output = result.stdout || "[]";
    const results = JSON.parse(output) as Array<{
      name: string;
      version: string;
      description: string;
      author?: { name?: string };
      keywords?: string[];
    }>;

    return results
      .filter((r) => r.name.startsWith(REGISTRY_PREFIX))
      .map((r) => ({
        name: r.name.replace(REGISTRY_PREFIX, ""),
        version: r.version,
        description: r.description,
        rules: 0, // can't know without downloading
        author: r.author?.name,
      }));
  } catch {
    return [];
  }
}

export async function installRulePack(
  name: string,
  projectPath: string
): Promise<{ rulesDir: string; ruleCount: number }> {
  const packageName = name.startsWith(REGISTRY_PREFIX)
    ? name
    : `${REGISTRY_PREFIX}${name}`;

  const rulesDir = path.join(projectPath, LOCAL_RULES_DIR);
  if (!fs.existsSync(rulesDir)) {
    fs.mkdirSync(rulesDir, { recursive: true });
  }

  // Download the package to a temp location
  const tempDir = path.join(projectPath, ".sphinx", ".tmp");
  fs.mkdirSync(tempDir, { recursive: true });

  if (!SAFE_NAME_PATTERN.test(packageName)) {
    throw new Error(`Invalid package name: ${packageName}`);
  }

  try {
    spawnSync(
      "npm",
      ["pack", packageName, "--pack-destination", tempDir],
      { encoding: "utf-8", timeout: 30000, stdio: "pipe" }
    );

    // Find the downloaded tarball
    const tarball = fs
      .readdirSync(tempDir)
      .find((f) => f.endsWith(".tgz"));
    if (!tarball) throw new Error("Package download failed");

    // Extract rules from the tarball
    spawnSync(
      "tar",
      ["-xzf", path.join(tempDir, tarball), "-C", tempDir],
      { stdio: "pipe" }
    );

    // Copy rule files to local rules directory
    const packageDir = path.join(tempDir, "package");
    const ruleFiles = findYamlFiles(packageDir);
    let ruleCount = 0;

    for (const ruleFile of ruleFiles) {
      const dest = path.join(
        rulesDir,
        `${name}-${path.basename(ruleFile)}`
      );
      fs.copyFileSync(ruleFile, dest);
      ruleCount++;
    }

    // Track installed packs
    trackInstalled(projectPath, name, packageName);

    return { rulesDir, ruleCount };
  } finally {
    // Cleanup temp
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

export function listInstalledPacks(
  projectPath: string
): Array<{ name: string; package: string }> {
  const trackFile = path.join(
    projectPath,
    LOCAL_RULES_DIR,
    ".installed.json"
  );
  if (!fs.existsSync(trackFile)) return [];

  try {
    return JSON.parse(fs.readFileSync(trackFile, "utf-8"));
  } catch {
    return [];
  }
}

export function uninstallRulePack(
  name: string,
  projectPath: string
): number {
  const rulesDir = path.join(projectPath, LOCAL_RULES_DIR);
  if (!fs.existsSync(rulesDir)) return 0;

  // Remove rule files prefixed with this pack name
  const files = fs.readdirSync(rulesDir);
  let removed = 0;
  for (const file of files) {
    if (file.startsWith(`${name}-`) && file.endsWith(".yml")) {
      fs.unlinkSync(path.join(rulesDir, file));
      removed++;
    }
  }

  // Update tracking
  const trackFile = path.join(rulesDir, ".installed.json");
  if (fs.existsSync(trackFile)) {
    const installed = JSON.parse(fs.readFileSync(trackFile, "utf-8")) as Array<{
      name: string;
    }>;
    const filtered = installed.filter((p) => p.name !== name);
    fs.writeFileSync(trackFile, JSON.stringify(filtered, null, 2));
  }

  return removed;
}

export function initRulePack(
  name: string,
  outputDir: string
): string {
  const packageName = `${REGISTRY_PREFIX}${name}`;
  const dir = path.join(outputDir, packageName);
  fs.mkdirSync(dir, { recursive: true });

  // Create package.json
  const pkg = {
    name: packageName,
    version: "1.0.0",
    description: `sphinx-agent security rules: ${name}`,
    keywords: ["sphinx-agent", "security", "rules", name],
    main: "rules.yml",
    files: ["*.yml"],
    license: "MIT",
  };
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify(pkg, null, 2)
  );

  // Create example rule file
  const exampleRules = `# ${name} — sphinx-agent custom rules
# Publish with: npm publish

rules:
  - id: ${name}-example
    title: Example rule from ${name} pack
    description: "Replace this with your actual rule description."
    severity: medium
    category: custom
    languages: ["*"]
    patterns:
      - pattern: "TODO_REPLACE_WITH_ACTUAL_PATTERN"
`;
  fs.writeFileSync(path.join(dir, "rules.yml"), exampleRules);

  // Create README
  const readme = `# ${packageName}

Custom security rules for [sphinx-agent](https://github.com/sphinx-agent/sphinx-agent).

## Install

\`\`\`bash
sphinx-agent rules install ${name}
\`\`\`

## Rules

| Rule | Severity | Description |
|------|----------|-------------|
| ${name}-example | medium | Example rule |

## Publish

\`\`\`bash
npm publish
\`\`\`
`;
  fs.writeFileSync(path.join(dir, "README.md"), readme);

  return dir;
}

function findYamlFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findYamlFiles(fullPath));
    } else if (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml")) {
      results.push(fullPath);
    }
  }
  return results;
}

function trackInstalled(
  projectPath: string,
  name: string,
  packageName: string
): void {
  const trackFile = path.join(
    projectPath,
    LOCAL_RULES_DIR,
    ".installed.json"
  );
  let installed: Array<{ name: string; package: string }> = [];
  if (fs.existsSync(trackFile)) {
    try {
      installed = JSON.parse(fs.readFileSync(trackFile, "utf-8"));
    } catch {
      // ignore
    }
  }
  if (!installed.find((p) => p.name === name)) {
    installed.push({ name, package: packageName });
  }
  fs.writeFileSync(trackFile, JSON.stringify(installed, null, 2));
}
