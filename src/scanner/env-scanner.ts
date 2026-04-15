import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

export interface EnvScanResult { findings: Vulnerability[]; filesScanned: number; }

export class EnvScanner {
  async scan(projectPath: string): Promise<EnvScanResult> {
    const envFiles = await glob(["**/.env", "**/.env.*", "**/.env.local", "**/.env.production"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**"], nodir: true, dot: true,
    });

    const findings: Vulnerability[] = [];
    let id = 1;

    for (const file of envFiles) {
      let content: string;
      try { content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      const isExample = rel.includes("example") || rel.includes("sample") || rel.includes("template");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith("#")) continue;
        const eqIdx = line.indexOf("=");
        if (eqIdx === -1) continue;
        const key = line.slice(0, eqIdx).trim();
        const value = line.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "");

        // Empty required-looking vars
        if (!value && !isExample && /(?:KEY|SECRET|TOKEN|PASSWORD|URL|DSN|CONNECTION)/i.test(key)) {
          findings.push({ id: `ENV-${String(id++).padStart(4, "0")}`, rule: "env:empty-required", title: `Env: Required variable "${key}" is empty`, description: `Environment variable "${key}" appears required but has no value. The application may fail or use insecure defaults.`, severity: "medium", category: "env", cwe: "CWE-1188", confidence: "medium", location: { file: rel, line: i + 1, snippet: line } });
        }

        // Default/placeholder values in non-example files
        if (!isExample && /^(changeme|password|secret|admin|test|example|default|TODO|xxx|placeholder|your_)/i.test(value)) {
          findings.push({ id: `ENV-${String(id++).padStart(4, "0")}`, rule: "env:default-value", title: `Env: Default/placeholder value for "${key}"`, description: `"${key}" has a placeholder value "${value}". Replace with a real, unique credential before deployment.`, severity: "high", category: "env", cwe: "CWE-1188", confidence: "high", location: { file: rel, line: i + 1, snippet: `${key}=${value.slice(0, 20)}...` } });
        }

        // DEBUG/development flags in production env
        if (rel.includes("production") || rel.includes("prod")) {
          if (/^(DEBUG|DEVELOPMENT|DEV_MODE|VERBOSE|LOG_LEVEL)$/i.test(key) && /^(true|1|yes|debug|verbose)$/i.test(value)) {
            findings.push({ id: `ENV-${String(id++).padStart(4, "0")}`, rule: "env:debug-in-prod", title: `Env: Debug flag enabled in production`, description: `"${key}=${value}" in production config. Debug features expose sensitive information.`, severity: "high", category: "env", cwe: "CWE-215", confidence: "high", location: { file: rel, line: i + 1, snippet: line } });
          }
        }

        // HTTP URLs for sensitive services (should be HTTPS)
        if (/^(API_URL|DATABASE_URL|SERVICE_URL|WEBHOOK_URL|CALLBACK_URL)/i.test(key) && value.startsWith("http://") && !value.includes("localhost") && !value.includes("127.0.0.1")) {
          findings.push({ id: `ENV-${String(id++).padStart(4, "0")}`, rule: "env:insecure-url", title: `Env: Non-HTTPS URL for "${key}"`, description: `"${key}" uses HTTP instead of HTTPS. Data transmitted in cleartext over the network.`, severity: "medium", category: "env", cwe: "CWE-319", confidence: "high", location: { file: rel, line: i + 1, snippet: `${key}=${value.slice(0, 40)}...` } });
        }

        // Env var injection via newlines
        if (value.includes("\\n") && /(?:HEADER|COOKIE|RESPONSE)/i.test(key)) {
          findings.push({ id: `ENV-${String(id++).padStart(4, "0")}`, rule: "env:injection", title: `Env: Possible header injection via "${key}"`, description: `"${key}" contains newline characters that could enable HTTP header injection if used in responses.`, severity: "medium", category: "env", cwe: "CWE-113", confidence: "low", location: { file: rel, line: i + 1, snippet: line.slice(0, 60) } });
        }
      }

      // Check if .env is in .gitignore
      if (rel === ".env" || rel === ".env.local" || rel === ".env.production") {
        const gitignorePath = path.join(projectPath, ".gitignore");
        if (fs.existsSync(gitignorePath)) {
          const gitignore = fs.readFileSync(gitignorePath, "utf-8");
          if (!gitignore.includes(".env")) {
            findings.push({ id: `ENV-${String(id++).padStart(4, "0")}`, rule: "env:not-gitignored", title: "Env: .env file not in .gitignore", description: ".env file exists but is not listed in .gitignore. It may be committed to version control, exposing secrets.", severity: "high", category: "env", cwe: "CWE-798", confidence: "high", location: { file: rel, line: 0, snippet: `${rel} not in .gitignore` } });
          }
        }
      }
    }

    return { findings, filesScanned: envFiles.length };
  }
}
