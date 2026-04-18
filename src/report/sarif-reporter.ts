import type { ScanResult, Vulnerability, Severity } from "../types/index.js";

interface SarifLevel {
  [key: string]: "error" | "warning" | "note" | "none";
}

const SEVERITY_TO_SARIF: SarifLevel = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

export function renderSarifReport(result: ScanResult): string {
  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mythos-agent",
            version: "0.2.0",
            informationUri: "https://github.com/mythos-agent/mythos-agent",
            rules: buildRules(result.confirmedVulnerabilities),
          },
        },
        results: result.confirmedVulnerabilities.map((v) => ({
          ruleId: v.rule,
          level: SEVERITY_TO_SARIF[v.severity] || "warning",
          message: {
            text: `${v.title}: ${v.description}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: v.location.file.replace(/\\/g, "/"),
                },
                region: {
                  startLine: v.location.line,
                  startColumn: v.location.column || 1,
                },
              },
            },
          ],
          properties: {
            severity: v.severity,
            confidence: v.confidence,
            aiVerified: v.aiVerified || false,
            ...(v.cwe ? { cwe: v.cwe } : {}),
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function buildRules(vulns: Vulnerability[]): Array<{
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  properties: { tags: string[] };
}> {
  const seen = new Set<string>();
  const rules: Array<{
    id: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    help: { text: string };
    properties: { tags: string[] };
  }> = [];

  for (const v of vulns) {
    if (seen.has(v.rule)) continue;
    seen.add(v.rule);

    rules.push({
      id: v.rule,
      shortDescription: { text: v.title },
      fullDescription: { text: v.description },
      help: { text: v.description },
      properties: {
        tags: [v.category, `severity:${v.severity}`, ...(v.cwe ? [v.cwe] : [])],
      },
    });
  }

  return rules;
}
