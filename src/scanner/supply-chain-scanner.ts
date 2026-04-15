import fs from "node:fs";
import path from "node:path";
import type { Vulnerability, Severity } from "../types/index.js";

export interface SupplyChainResult {
  findings: Vulnerability[];
}

// Known typosquatting patterns — popular package + common typos
const TYPOSQUAT_TARGETS: Record<string, string[]> = {
  "lodash": ["lodahs", "lodasah", "1odash", "l0dash"],
  "express": ["expres", "expresss", "axpress", "expess"],
  "react": ["raect", "recat", "reat", "reactt"],
  "axios": ["axois", "axio", "axioss", "axos"],
  "moment": ["momnet", "momet", "monment"],
  "chalk": ["chalck", "chalks", "chak"],
  "dotenv": ["dot-env", "dotnev", "dotenvv"],
  "jsonwebtoken": ["json-webtoken", "jsonwebtokem", "jasonwebtoken"],
  "bcrypt": ["bycrypt", "bcryot", "bcyrpt"],
  "mongoose": ["mongose", "mongeese", "mongooes"],
  "sequelize": ["seqelize", "sqeuelize", "sequlize"],
  "passport": ["pasport", "passort", "passpoort"],
  "helmet": ["helment", "helmett", "hemlet"],
  "cors": ["coors", "corss"],
};

export class SupplyChainScanner {
  async scan(projectPath: string): Promise<SupplyChainResult> {
    const findings: Vulnerability[] = [];
    let idCounter = 1;

    // Check package.json for suspicious patterns
    const pkgPath = path.join(projectPath, "package.json");
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        const allDeps = {
          ...pkg.dependencies,
          ...pkg.devDependencies,
        };

        // 1. Typosquatting detection
        for (const [depName] of Object.entries(allDeps || {})) {
          for (const [legit, typos] of Object.entries(TYPOSQUAT_TARGETS)) {
            if (typos.includes(depName.toLowerCase())) {
              findings.push({
                id: `SUPPLY-${String(idCounter++).padStart(4, "0")}`,
                rule: "supply:typosquat",
                title: `Supply Chain: Possible typosquatting package "${depName}"`,
                description: `Package "${depName}" looks like a typo of "${legit}". Typosquatting packages often contain malware. Verify this is the correct package.`,
                severity: "critical",
                category: "supply-chain",
                cwe: "CWE-829",
                confidence: "high",
                location: { file: "package.json", line: 0, snippet: `"${depName}"` },
              });
            }
          }

          // 2. Suspicious package name patterns
          if (/^[a-z]+-[a-z]+-[a-z]+-[a-z]+$/.test(depName) && !depName.startsWith("@")) {
            // Very generic multi-word name — common in malicious packages
          }
        }

        // 3. Preinstall/postinstall scripts
        if (pkg.scripts) {
          for (const [scriptName, scriptCmd] of Object.entries(pkg.scripts)) {
            const cmd = scriptCmd as string;
            if (
              (scriptName === "preinstall" || scriptName === "postinstall" || scriptName === "prepare") &&
              /(?:curl|wget|bash|sh|powershell|cmd|node\s+-e|eval|exec|child_process|http|https)/.test(cmd)
            ) {
              findings.push({
                id: `SUPPLY-${String(idCounter++).padStart(4, "0")}`,
                rule: "supply:dangerous-install-script",
                title: `Supply Chain: Dangerous ${scriptName} script`,
                description: `The ${scriptName} script contains potentially dangerous commands: "${cmd.slice(0, 100)}". Install scripts can execute arbitrary code during npm install.`,
                severity: "high",
                category: "supply-chain",
                cwe: "CWE-829",
                confidence: "high",
                location: { file: "package.json", line: 0, snippet: `"${scriptName}": "${cmd.slice(0, 80)}"` },
              });
            }
          }
        }

        // 4. Git URL dependencies (potential dependency confusion)
        for (const [depName, version] of Object.entries(allDeps || {})) {
          const v = version as string;
          if (v.startsWith("git+") || v.startsWith("git://") || v.includes("github.com")) {
            findings.push({
              id: `SUPPLY-${String(idCounter++).padStart(4, "0")}`,
              rule: "supply:git-dependency",
              title: `Supply Chain: Git URL dependency "${depName}"`,
              description: `Package "${depName}" is loaded from a git URL instead of the npm registry. This bypasses npm's integrity checks and could be replaced with a malicious version.`,
              severity: "medium",
              category: "supply-chain",
              cwe: "CWE-829",
              confidence: "medium",
              location: { file: "package.json", line: 0, snippet: `"${depName}": "${v.slice(0, 60)}"` },
            });
          }

          // 5. Unpinned dependencies (no lockfile integrity)
          if (v === "*" || v === "latest" || v.startsWith(">")) {
            findings.push({
              id: `SUPPLY-${String(idCounter++).padStart(4, "0")}`,
              rule: "supply:unpinned-dependency",
              title: `Supply Chain: Unpinned dependency "${depName}"`,
              description: `Package "${depName}" version "${v}" is not pinned. A compromised future version could be installed automatically.`,
              severity: "medium",
              category: "supply-chain",
              cwe: "CWE-1104",
              confidence: "high",
              location: { file: "package.json", line: 0, snippet: `"${depName}": "${v}"` },
            });
          }
        }

        // 6. No lockfile
        const hasLockfile = fs.existsSync(path.join(projectPath, "package-lock.json")) ||
          fs.existsSync(path.join(projectPath, "yarn.lock")) ||
          fs.existsSync(path.join(projectPath, "pnpm-lock.yaml"));
        if (!hasLockfile && Object.keys(allDeps || {}).length > 0) {
          findings.push({
            id: `SUPPLY-${String(idCounter++).padStart(4, "0")}`,
            rule: "supply:no-lockfile",
            title: "Supply Chain: No lockfile found",
            description: "No package-lock.json, yarn.lock, or pnpm-lock.yaml found. Without a lockfile, dependency versions aren't deterministic and integrity can't be verified.",
            severity: "high",
            category: "supply-chain",
            cwe: "CWE-1104",
            confidence: "high",
            location: { file: "package.json", line: 0 },
          });
        }
      } catch {
        // parse error
      }
    }

    // Check requirements.txt for Python supply chain issues
    const reqPath = path.join(projectPath, "requirements.txt");
    if (fs.existsSync(reqPath)) {
      const content = fs.readFileSync(reqPath, "utf-8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith("#")) continue;

        // Unpinned Python dependencies
        if (line.match(/^[a-zA-Z0-9_.-]+$/) && !line.includes("==")) {
          findings.push({
            id: `SUPPLY-${String(idCounter++).padStart(4, "0")}`,
            rule: "supply:unpinned-python-dep",
            title: `Supply Chain: Unpinned Python dependency "${line}"`,
            description: `Python package "${line}" has no version pin. Use == to pin to a specific version.`,
            severity: "medium",
            category: "supply-chain",
            cwe: "CWE-1104",
            confidence: "high",
            location: { file: "requirements.txt", line: i + 1, snippet: line },
          });
        }

        // --extra-index-url (dependency confusion)
        if (line.includes("--extra-index-url") || line.includes("--index-url")) {
          findings.push({
            id: `SUPPLY-${String(idCounter++).padStart(4, "0")}`,
            rule: "supply:custom-index",
            title: "Supply Chain: Custom package index URL",
            description: "Custom package index URL found. This could enable dependency confusion attacks where a malicious public package overrides an internal one.",
            severity: "high",
            category: "supply-chain",
            cwe: "CWE-829",
            confidence: "high",
            location: { file: "requirements.txt", line: i + 1, snippet: line },
          });
        }
      }
    }

    return { findings };
  }
}
