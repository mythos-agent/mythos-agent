import type { Vulnerability, Severity } from "../types/index.js";
import {
  discoverLockfiles,
  parseLockfile,
  type Dependency,
} from "./lockfile-parsers.js";

interface OsvVulnerability {
  id: string;
  summary: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: Array<{
    package?: {
      name: string;
      ecosystem: string;
    };
    ranges?: Array<{
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  database_specific?: {
    severity?: string;
  };
}

interface OsvResponse {
  vulns?: OsvVulnerability[];
}

export interface DepScanResult {
  findings: Vulnerability[];
  totalDependencies: number;
  lockfilesScanned: number;
}

const BATCH_SIZE = 100;
const OSV_API = "https://api.osv.dev/v1";

export class DepScanner {
  async scan(projectPath: string): Promise<DepScanResult> {
    const lockfiles = discoverLockfiles(projectPath);
    if (lockfiles.length === 0) {
      return { findings: [], totalDependencies: 0, lockfilesScanned: 0 };
    }

    // Parse all lockfiles
    const allDeps: Dependency[] = [];
    for (const lockfile of lockfiles) {
      const deps = parseLockfile(lockfile);
      allDeps.push(...deps);
    }

    // Deduplicate
    const seen = new Set<string>();
    const uniqueDeps = allDeps.filter((d) => {
      const key = `${d.ecosystem}:${d.name}@${d.version}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Query OSV in batches
    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (let i = 0; i < uniqueDeps.length; i += BATCH_SIZE) {
      const batch = uniqueDeps.slice(i, i + BATCH_SIZE);
      const batchResults = await this.queryOsvBatch(batch);

      for (const result of batchResults) {
        if (!result.vulns || result.vulns.length === 0) continue;

        const dep = result.dep;
        for (const vuln of result.vulns) {
          const cve = vuln.aliases?.find((a) => a.startsWith("CVE-"));
          const severity = this.extractSeverity(vuln);

          findings.push({
            id: `DEP-${String(idCounter++).padStart(4, "0")}`,
            rule: `dep:${vuln.id}`,
            title: `${dep.name}@${dep.version}: ${vuln.summary || vuln.id}`,
            description: vuln.details
              ? vuln.details.slice(0, 300)
              : vuln.summary || "Known vulnerability in dependency",
            severity,
            category: "dependency",
            cwe: cve,
            confidence: "high",
            location: {
              file: dep.lockfile,
              line: 0,
              snippet: `${dep.name}@${dep.version} (${dep.ecosystem})`,
            },
          });
        }
      }
    }

    return {
      findings,
      totalDependencies: uniqueDeps.length,
      lockfilesScanned: lockfiles.length,
    };
  }

  private async queryOsvBatch(
    deps: Dependency[]
  ): Promise<Array<{ dep: Dependency; vulns: OsvVulnerability[] }>> {
    const results: Array<{ dep: Dependency; vulns: OsvVulnerability[] }> = [];

    // OSV querybatch endpoint
    const queries = deps.map((dep) => ({
      package: {
        name: dep.name,
        ecosystem: dep.ecosystem,
      },
      version: dep.version,
    }));

    try {
      const response = await fetch(`${OSV_API}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
      });

      if (!response.ok) {
        // Fallback to individual queries
        return this.queryOsvIndividual(deps);
      }

      const data = (await response.json()) as {
        results: Array<{ vulns?: OsvVulnerability[] }>;
      };

      for (let i = 0; i < deps.length; i++) {
        const vulns = data.results?.[i]?.vulns || [];
        if (vulns.length > 0) {
          results.push({ dep: deps[i], vulns });
        }
      }
    } catch {
      // Network error — try individual queries as fallback
      return this.queryOsvIndividual(deps);
    }

    return results;
  }

  private async queryOsvIndividual(
    deps: Dependency[]
  ): Promise<Array<{ dep: Dependency; vulns: OsvVulnerability[] }>> {
    const results: Array<{ dep: Dependency; vulns: OsvVulnerability[] }> = [];

    for (const dep of deps) {
      try {
        const response = await fetch(`${OSV_API}/query`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            package: {
              name: dep.name,
              ecosystem: dep.ecosystem,
            },
            version: dep.version,
          }),
        });

        if (response.ok) {
          const data = (await response.json()) as OsvResponse;
          if (data.vulns && data.vulns.length > 0) {
            results.push({ dep, vulns: data.vulns });
          }
        }
      } catch {
        // skip this dep on error
      }
    }

    return results;
  }

  private extractSeverity(vuln: OsvVulnerability): Severity {
    // Try CVSS score first
    const cvss = vuln.severity?.find((s) => s.type === "CVSS_V3");
    if (cvss) {
      const score = parseFloat(cvss.score);
      if (score >= 9.0) return "critical";
      if (score >= 7.0) return "high";
      if (score >= 4.0) return "medium";
      return "low";
    }

    // Try database_specific severity
    const dbSeverity = vuln.database_specific?.severity?.toLowerCase();
    if (dbSeverity === "critical") return "critical";
    if (dbSeverity === "high") return "high";
    if (dbSeverity === "moderate" || dbSeverity === "medium") return "medium";
    if (dbSeverity === "low") return "low";

    // Default to high for known vulnerabilities
    return "high";
  }
}
