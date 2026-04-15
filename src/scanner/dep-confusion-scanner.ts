import fs from "node:fs";
import path from "node:path";
import type { Vulnerability } from "../types/index.js";

export interface DepConfusionScanResult { findings: Vulnerability[]; }

export class DepConfusionScanner {
  async scan(projectPath: string): Promise<DepConfusionScanResult> {
    const findings: Vulnerability[] = [];
    let id = 1;

    // Check package.json for private packages without scope
    const pkgPath = path.join(projectPath, "package.json");
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

        for (const [name, version] of Object.entries(allDeps || {})) {
          const v = version as string;

          // Private registry URL — check if public name is claimable
          if (v.includes("registry") && !name.startsWith("@")) {
            findings.push({
              id: `DEPCON-${String(id++).padStart(4, "0")}`,
              rule: "depcon:unscoped-private",
              title: `Dep Confusion: Unscoped private package "${name}"`,
              description: `Package "${name}" uses a private registry but is not scoped (@org/name). An attacker could register "${name}" on npm with a higher version to hijack installations.`,
              severity: "critical",
              category: "supply-chain",
              cwe: "CWE-427",
              confidence: "high",
              location: { file: "package.json", line: 0, snippet: `"${name}": "${v}"` },
            });
          }
        }

        // Check if package itself is private but unscoped
        if (pkg.private !== true && pkg.name && !pkg.name.startsWith("@") && !pkg.name.includes("/")) {
          // Check for internal-looking names
          if (/^(?:internal|private|company|corp|org)-/.test(pkg.name) || pkg.publishConfig?.registry) {
            findings.push({
              id: `DEPCON-${String(id++).padStart(4, "0")}`,
              rule: "depcon:claimable-name",
              title: `Dep Confusion: Package name "${pkg.name}" may be claimable on npm`,
              description: `This package has an internal-looking name but isn't scoped or marked private. Someone could register "${pkg.name}" on npm. Add "private": true or use @scope/name.`,
              severity: "high",
              category: "supply-chain",
              cwe: "CWE-427",
              confidence: "medium",
              location: { file: "package.json", line: 0, snippet: `"name": "${pkg.name}"` },
            });
          }
        }
      } catch { /* parse error */ }
    }

    // Check .npmrc for risky config
    const npmrcPath = path.join(projectPath, ".npmrc");
    if (fs.existsSync(npmrcPath)) {
      const content = fs.readFileSync(npmrcPath, "utf-8");
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // Registry pointing to internal but no scope
        if (line.startsWith("registry=") && !line.includes("npmjs.org") && !line.includes("npmjs.com")) {
          findings.push({
            id: `DEPCON-${String(id++).padStart(4, "0")}`,
            rule: "depcon:global-private-registry",
            title: "Dep Confusion: Global registry set to private",
            description: "Global npm registry points to a private server. Unscoped packages will be fetched from here, but scoped packages may still go to public npm. Use per-scope registry config instead.",
            severity: "medium",
            category: "supply-chain",
            cwe: "CWE-427",
            confidence: "medium",
            location: { file: ".npmrc", line: i + 1, snippet: line },
          });
        }

        // Auth token in .npmrc (should be in env)
        if (line.includes("_authToken=") && !line.includes("${")) {
          findings.push({
            id: `DEPCON-${String(id++).padStart(4, "0")}`,
            rule: "depcon:auth-token-hardcoded",
            title: "Dep Confusion: Auth token hardcoded in .npmrc",
            description: "NPM auth token hardcoded instead of using environment variable. Use ${NPM_TOKEN} placeholder.",
            severity: "high",
            category: "secrets",
            cwe: "CWE-798",
            confidence: "high",
            location: { file: ".npmrc", line: i + 1, snippet: line.slice(0, 40) + "..." },
          });
        }
      }
    }

    // Check pip.conf / pip.ini for Python dep confusion
    for (const pipConfig of ["pip.conf", "pip.ini", ".pip/pip.conf"]) {
      const pipPath = path.join(projectPath, pipConfig);
      if (fs.existsSync(pipPath)) {
        const content = fs.readFileSync(pipPath, "utf-8");
        if (content.includes("extra-index-url") || content.includes("index-url")) {
          findings.push({
            id: `DEPCON-${String(id++).padStart(4, "0")}`,
            rule: "depcon:python-extra-index",
            title: "Dep Confusion: Python extra-index-url configured",
            description: "pip configured with extra-index-url. Packages are searched on both public PyPI and the private index. An attacker can register a higher version on PyPI to hijack.",
            severity: "high",
            category: "supply-chain",
            cwe: "CWE-427",
            confidence: "high",
            location: { file: pipConfig, line: 0 },
          });
        }
      }
    }

    return { findings };
  }
}
