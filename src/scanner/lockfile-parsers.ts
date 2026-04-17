import fs from "node:fs";
import path from "node:path";

export interface Dependency {
  name: string;
  version: string;
  ecosystem: string;
  lockfile: string;
}

export function discoverLockfiles(projectPath: string): string[] {
  const lockfiles = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "pom.xml",
    "build.gradle",
  ];

  return lockfiles.map((f) => path.join(projectPath, f)).filter((f) => fs.existsSync(f));
}

export function parseLockfile(filePath: string): Dependency[] {
  const filename = path.basename(filePath);

  switch (filename) {
    case "package-lock.json":
      return parseNpmLockfile(filePath);
    case "yarn.lock":
      return parseYarnLockfile(filePath);
    case "requirements.txt":
      return parsePipRequirements(filePath);
    case "Pipfile.lock":
      return parsePipfileLock(filePath);
    case "go.sum":
      return parseGoSum(filePath);
    case "Cargo.lock":
      return parseCargoLock(filePath);
    case "Gemfile.lock":
      return parseGemfileLock(filePath);
    case "composer.lock":
      return parseComposerLock(filePath);
    default:
      return [];
  }
}

function parseNpmLockfile(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const raw = JSON.parse(fs.readFileSync(filePath, "utf-8"));

    // npm v2/v3 lockfile format (lockfileVersion 2 or 3)
    if (raw.packages) {
      for (const [pkgPath, info] of Object.entries(raw.packages)) {
        if (!pkgPath || pkgPath === "") continue; // skip root
        const pkg = info as { version?: string };
        if (!pkg.version) continue;

        const name = pkgPath.replace(/^node_modules\//, "");
        deps.push({
          name,
          version: pkg.version,
          ecosystem: "npm",
          lockfile: "package-lock.json",
        });
      }
    }
    // npm v1 lockfile format
    else if (raw.dependencies) {
      for (const [name, info] of Object.entries(raw.dependencies)) {
        const pkg = info as { version?: string };
        if (pkg.version) {
          deps.push({
            name,
            version: pkg.version,
            ecosystem: "npm",
            lockfile: "package-lock.json",
          });
        }
      }
    }
  } catch {
    // ignore parse errors
  }
  return deps;
}

function parseYarnLockfile(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    // Simple yarn.lock parser: look for "name@version:" and "version" lines
    const blocks = content.split(/\n(?=\S)/);
    for (const block of blocks) {
      const headerMatch = block.match(/^"?([^@\s"]+)@/);
      const versionMatch = block.match(/^\s+version\s+"?([^"\s]+)"?/m);
      if (headerMatch && versionMatch) {
        deps.push({
          name: headerMatch[1],
          version: versionMatch[1],
          ecosystem: "npm",
          lockfile: "yarn.lock",
        });
      }
    }
  } catch {
    // ignore
  }
  return deps;
}

function parsePipRequirements(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

      const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*==\s*([^\s;#]+)/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: "PyPI",
          lockfile: "requirements.txt",
        });
      }
    }
  } catch {
    // ignore
  }
  return deps;
}

function parsePipfileLock(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const raw = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    for (const section of ["default", "develop"]) {
      const packages = raw[section];
      if (!packages) continue;
      for (const [name, info] of Object.entries(packages)) {
        const pkg = info as { version?: string };
        if (pkg.version) {
          deps.push({
            name,
            version: pkg.version.replace(/^==/, ""),
            ecosystem: "PyPI",
            lockfile: "Pipfile.lock",
          });
        }
      }
    }
  } catch {
    // ignore
  }
  return deps;
}

function parseGoSum(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  const seen = new Set<string>();
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    for (const line of content.split("\n")) {
      const match = line.match(/^(\S+)\s+v([^\s/]+)/);
      if (match) {
        const key = `${match[1]}@${match[2]}`;
        if (seen.has(key)) continue;
        seen.add(key);
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: "Go",
          lockfile: "go.sum",
        });
      }
    }
  } catch {
    // ignore
  }
  return deps;
}

function parseCargoLock(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    const packageBlocks = content.split("[[package]]");
    for (const block of packageBlocks) {
      const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
      const versionMatch = block.match(/version\s*=\s*"([^"]+)"/);
      if (nameMatch && versionMatch) {
        deps.push({
          name: nameMatch[1],
          version: versionMatch[1],
          ecosystem: "crates.io",
          lockfile: "Cargo.lock",
        });
      }
    }
  } catch {
    // ignore
  }
  return deps;
}

function parseGemfileLock(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    const lines = content.split("\n");
    let inSpecs = false;
    for (const line of lines) {
      if (line.trim() === "specs:") {
        inSpecs = true;
        continue;
      }
      if (inSpecs && line.match(/^\s{4}\S/)) {
        const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            ecosystem: "RubyGems",
            lockfile: "Gemfile.lock",
          });
        }
      } else if (inSpecs && !line.match(/^\s/)) {
        inSpecs = false;
      }
    }
  } catch {
    // ignore
  }
  return deps;
}

function parseComposerLock(filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const raw = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    for (const section of ["packages", "packages-dev"]) {
      const packages = raw[section];
      if (!Array.isArray(packages)) continue;
      for (const pkg of packages) {
        if (pkg.name && pkg.version) {
          deps.push({
            name: pkg.name,
            version: pkg.version.replace(/^v/, ""),
            ecosystem: "Packagist",
            lockfile: "composer.lock",
          });
        }
      }
    }
  } catch {
    // ignore
  }
  return deps;
}
