import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";

interface ExportOptions {
  path?: string;
  format: string;
  output?: string;
}

export async function exportCommand(options: ExportOptions) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(chalk.yellow("\n⚠️  No scan results. Run shedu scan first.\n"));
    return;
  }

  const vulns = result.confirmedVulnerabilities;
  let output: string;

  switch (options.format) {
    case "csv":
      output = exportCsv(vulns);
      break;
    case "jira":
      output = exportJira(vulns);
      break;
    case "linear":
      output = exportLinear(vulns);
      break;
    case "github":
      output = exportGitHubIssues(vulns);
      break;
    default:
      output = exportCsv(vulns);
  }

  if (options.output) {
    const outputPath = path.resolve(options.output);
    fs.writeFileSync(outputPath, output, "utf-8");
    console.log(
      chalk.green(
        `\n✅ Exported ${vulns.length} findings as ${options.format.toUpperCase()} to ${outputPath}\n`
      )
    );
  } else {
    console.log(output);
  }
}

function exportCsv(
  vulns: Array<{
    id: string;
    severity: string;
    title: string;
    category: string;
    cwe?: string;
    location: { file: string; line: number; snippet?: string };
  }>
): string {
  const header = "ID,Severity,Title,Category,CWE,File,Line,Snippet";
  const rows = vulns.map(
    (v) =>
      `${v.id},${v.severity},"${v.title.replace(/"/g, '""')}",${v.category},${v.cwe || ""},${v.location.file},${v.location.line},"${(v.location.snippet || "").replace(/"/g, '""')}"`
  );
  return [header, ...rows].join("\n");
}

function exportJira(
  vulns: Array<{
    id: string;
    severity: string;
    title: string;
    description: string;
    category: string;
    cwe?: string;
    location: { file: string; line: number };
  }>
): string {
  return vulns
    .map((v) => {
      const priority =
        v.severity === "critical"
          ? "Highest"
          : v.severity === "high"
            ? "High"
            : v.severity === "medium"
              ? "Medium"
              : "Low";
      return `## ${v.id}: ${v.title}

**Priority:** ${priority}
**Category:** ${v.category}
**CWE:** ${v.cwe || "N/A"}
**File:** ${v.location.file}:${v.location.line}

### Description
${v.description}

### Acceptance Criteria
- [ ] Vulnerability is fixed
- [ ] Fix verified by re-running shedu scan
- [ ] No regressions introduced

---
`;
    })
    .join("\n");
}

function exportLinear(
  vulns: Array<{
    id: string;
    severity: string;
    title: string;
    description: string;
    location: { file: string; line: number };
  }>
): string {
  return JSON.stringify(
    vulns.map((v) => ({
      title: `[Security] ${v.id}: ${v.title}`,
      description: `**File:** \`${v.location.file}:${v.location.line}\`\n\n${v.description}\n\n*Found by shedu*`,
      priority:
        v.severity === "critical" ? 1 : v.severity === "high" ? 2 : v.severity === "medium" ? 3 : 4,
      labels: ["security", v.severity],
    })),
    null,
    2
  );
}

function exportGitHubIssues(
  vulns: Array<{
    id: string;
    severity: string;
    title: string;
    description: string;
    category: string;
    cwe?: string;
    location: { file: string; line: number };
  }>
): string {
  return vulns
    .map((v) => {
      const label =
        v.severity === "critical" || v.severity === "high" ? "priority: high" : "priority: medium";
      return `---
title: "[Security] ${v.id}: ${v.title}"
labels: [security, ${v.category}, ${label}]
---

## Security Finding: ${v.title}

| Field | Value |
|-------|-------|
| ID | ${v.id} |
| Severity | ${v.severity} |
| Category | ${v.category} |
| CWE | ${v.cwe || "N/A"} |
| File | \`${v.location.file}:${v.location.line}\` |

### Description
${v.description}

### Remediation
- [ ] Fix the vulnerability
- [ ] Run \`shedu scan\` to verify
- [ ] No regressions

*Found by [shedu](https://github.com/zhijiewong/shedu)*
`;
    })
    .join("\n---\n\n");
}
