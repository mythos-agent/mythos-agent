import fs from "node:fs";
import path from "node:path";
import type { ScanResult, Vulnerability } from "../types/index.js";
import { getComplianceMapping } from "../policy/engine.js";

export interface ComplianceControl {
  framework: string;
  controlId: string;
  description: string;
  status: "pass" | "fail" | "partial";
  findings: Vulnerability[];
}

const FRAMEWORKS: Record<
  string,
  Array<{ id: string; description: string; categories: string[] }>
> = {
  SOC2: [
    {
      id: "CC6.1",
      description: "Logical and Physical Access Controls",
      categories: ["injection", "xss", "auth"],
    },
    {
      id: "CC6.2",
      description: "System Operations — Security Monitoring",
      categories: ["secrets", "config"],
    },
    { id: "CC6.6", description: "Confidentiality — Encryption", categories: ["crypto"] },
    {
      id: "CC6.7",
      description: "Confidentiality — Data Transmission",
      categories: ["crypto", "config"],
    },
    { id: "CC7.1", description: "System Monitoring for Anomalies", categories: ["config", "iac"] },
    { id: "CC7.2", description: "Incident Response", categories: [] },
    { id: "CC8.1", description: "Change Management", categories: ["dependency"] },
  ],
  HIPAA: [
    {
      id: "§164.312(a)(1)",
      description: "Access Control",
      categories: ["injection", "auth", "access-control"],
    },
    {
      id: "§164.312(a)(2)(iv)",
      description: "Encryption and Decryption",
      categories: ["crypto", "secrets"],
    },
    { id: "§164.312(b)", description: "Audit Controls", categories: ["config"] },
    { id: "§164.312(c)(1)", description: "Integrity Controls", categories: ["injection", "xss"] },
    { id: "§164.312(d)", description: "Authentication", categories: ["auth", "crypto"] },
    {
      id: "§164.312(e)(1)",
      description: "Transmission Security",
      categories: ["crypto", "config"],
    },
  ],
  "PCI-DSS": [
    { id: "Req 2.2", description: "System Configuration Standards", categories: ["config", "iac"] },
    { id: "Req 3.4", description: "Render PAN Unreadable", categories: ["secrets", "crypto"] },
    { id: "Req 4.1", description: "Strong Cryptography for Transmission", categories: ["crypto"] },
    { id: "Req 6.5.1", description: "Injection Flaws", categories: ["injection"] },
    { id: "Req 6.5.7", description: "Cross-Site Scripting", categories: ["xss"] },
    {
      id: "Req 6.5.8",
      description: "Improper Access Control",
      categories: ["auth", "access-control"],
    },
    { id: "Req 6.5.9", description: "Cross-Site Request Forgery", categories: ["auth"] },
    { id: "Req 6.5.10", description: "Broken Authentication", categories: ["auth", "crypto"] },
    { id: "Req 6.6", description: "Vulnerability Scanning", categories: [] },
    { id: "Req 8.2", description: "Authentication Management", categories: ["auth", "secrets"] },
    { id: "Req 11.2", description: "Vulnerability Scans", categories: [] },
  ],
  OWASP: [
    {
      id: "A01:2021",
      description: "Broken Access Control",
      categories: ["auth", "access-control", "redirect"],
    },
    { id: "A02:2021", description: "Cryptographic Failures", categories: ["crypto", "secrets"] },
    { id: "A03:2021", description: "Injection", categories: ["injection", "xss"] },
    { id: "A04:2021", description: "Insecure Design", categories: ["business-logic"] },
    { id: "A05:2021", description: "Security Misconfiguration", categories: ["config", "iac"] },
    { id: "A06:2021", description: "Vulnerable Components", categories: ["dependency"] },
    { id: "A07:2021", description: "Auth Failures", categories: ["auth"] },
    {
      id: "A08:2021",
      description: "Software and Data Integrity",
      categories: ["dependency", "config"],
    },
    { id: "A09:2021", description: "Logging and Monitoring", categories: [] },
    { id: "A10:2021", description: "Server-Side Request Forgery", categories: ["ssrf"] },
  ],
};

export function generateComplianceReport(
  result: ScanResult,
  frameworks: string[]
): {
  framework: string;
  controls: ComplianceControl[];
  passRate: number;
}[] {
  const reports: {
    framework: string;
    controls: ComplianceControl[];
    passRate: number;
  }[] = [];

  const vulns = result.confirmedVulnerabilities;

  for (const framework of frameworks) {
    const controlDefs = FRAMEWORKS[framework];
    if (!controlDefs) continue;

    const controls: ComplianceControl[] = controlDefs.map((ctrl) => {
      const relatedFindings = vulns.filter((v) => ctrl.categories.includes(v.category));

      const hasCriticalOrHigh = relatedFindings.some(
        (f) => f.severity === "critical" || f.severity === "high"
      );

      return {
        framework,
        controlId: ctrl.id,
        description: ctrl.description,
        status: relatedFindings.length === 0 ? "pass" : hasCriticalOrHigh ? "fail" : "partial",
        findings: relatedFindings,
      };
    });

    const passCount = controls.filter((c) => c.status === "pass").length;
    const passRate = Math.round((passCount / controls.length) * 100);

    reports.push({ framework, controls, passRate });
  }

  return reports;
}

export function renderComplianceMarkdown(
  result: ScanResult,
  frameworks: string[],
  projectPath: string
): string {
  const reports = generateComplianceReport(result, frameworks);
  const projectName = path.basename(projectPath);
  const date = new Date().toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  let md = `# Compliance Report: ${projectName}\n\n`;
  md += `**Date:** ${date}\n**Tool:** sphinx-agent v1.0.0\n\n---\n\n`;

  for (const report of reports) {
    md += `## ${report.framework} Compliance (${report.passRate}% pass rate)\n\n`;
    md += `| Status | Control | Description | Findings |\n`;
    md += `|--------|---------|-------------|----------|\n`;

    for (const ctrl of report.controls) {
      const icon = ctrl.status === "pass" ? "✅" : ctrl.status === "fail" ? "❌" : "⚠️";
      md += `| ${icon} ${ctrl.status} | ${ctrl.controlId} | ${ctrl.description} | ${ctrl.findings.length} |\n`;
    }

    md += `\n`;

    // Detail failed controls
    const failed = report.controls.filter((c) => c.status === "fail");
    if (failed.length > 0) {
      md += `### Failed Controls\n\n`;
      for (const ctrl of failed) {
        md += `#### ${ctrl.controlId}: ${ctrl.description}\n\n`;
        for (const f of ctrl.findings.slice(0, 5)) {
          md += `- **${f.id}** [${f.severity}] ${f.title} — \`${f.location.file}:${f.location.line}\`\n`;
        }
        md += `\n`;
      }
    }
  }

  md += `---\n\n*Generated by [sphinx-agent](https://github.com/sphinx-agent/sphinx-agent)*\n`;
  return md;
}

export function saveComplianceReport(
  result: ScanResult,
  frameworks: string[],
  projectPath: string
): string {
  const md = renderComplianceMarkdown(result, frameworks, projectPath);
  const dir = path.join(projectPath, ".sphinx");
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const outputPath = path.join(dir, "compliance-report.md");
  fs.writeFileSync(outputPath, md, "utf-8");
  return outputPath;
}
