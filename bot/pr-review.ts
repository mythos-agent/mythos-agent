#!/usr/bin/env node

/**
 * sphinx-agent PR Review Bot
 *
 * Scans PR diffs for security vulnerabilities and posts review comments.
 * Designed to run as a GitHub Action step.
 *
 * Environment variables:
 *   GITHUB_TOKEN          — GitHub token for posting comments
 *   GITHUB_REPOSITORY     — owner/repo
 *   GITHUB_EVENT_PATH     — path to event JSON
 *   MYTHOH_API_KEY        — (optional) Anthropic API key for AI analysis
 */

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

interface PREvent {
  pull_request: {
    number: number;
    head: { sha: string };
    base: { sha: string; ref: string };
  };
}

interface ScanFinding {
  file: string;
  line: number;
  title: string;
  description: string;
  severity: string;
  rule: string;
  cwe?: string;
  snippet?: string;
}

interface ReviewComment {
  path: string;
  line: number;
  body: string;
}

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;

  if (!token || !repo || !eventPath) {
    console.error("Missing required environment variables");
    process.exit(1);
  }

  const event: PREvent = JSON.parse(fs.readFileSync(eventPath, "utf-8"));
  const prNumber = event.pull_request.number;
  const baseSha = event.pull_request.base.sha;

  console.log(`sphinx-agent: Scanning PR #${prNumber} in ${repo}`);

  // Get changed files
  const diffOutput = execSync(
    `git diff --name-only ${baseSha}...HEAD`,
    { encoding: "utf-8" }
  ).trim();

  const changedFiles = diffOutput.split("\n").filter((f) => f.trim());
  if (changedFiles.length === 0) {
    console.log("No changed files to scan");
    return;
  }

  // Run sphinx-agent scan
  const scanOutput = execSync(
    `npx sphinx-agent scan . --diff ${baseSha} --no-ai --no-chain --json`,
    { encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 }
  );

  let scanResult: {
    summary: { total_vulnerabilities: number };
    vulnerabilities: ScanFinding[];
  };

  try {
    scanResult = JSON.parse(scanOutput);
  } catch {
    console.error("Failed to parse scan output");
    return;
  }

  const findings = scanResult.vulnerabilities || [];

  // Build review comments for findings in changed files
  const changedSet = new Set(changedFiles);
  const relevantFindings = findings.filter((f) =>
    changedSet.has(f.file.replace(/\\/g, "/"))
  );

  const comments: ReviewComment[] = relevantFindings.map((f) => ({
    path: f.file.replace(/\\/g, "/"),
    line: f.line,
    body: formatComment(f),
  }));

  // Post summary comment
  const summaryBody = buildSummaryComment(findings, relevantFindings, changedFiles.length);

  await githubApi(
    `repos/${repo}/issues/${prNumber}/comments`,
    token,
    { body: summaryBody }
  );

  // Post inline review comments
  if (comments.length > 0) {
    await githubApi(
      `repos/${repo}/pulls/${prNumber}/reviews`,
      token,
      {
        commit_id: event.pull_request.head.sha,
        body: "",
        event: "COMMENT",
        comments: comments.slice(0, 50), // GitHub limits to 50 comments per review
      }
    );
  }

  console.log(
    `sphinx-agent: Posted ${comments.length} inline comments + summary on PR #${prNumber}`
  );

  // Exit with error if critical/high vulns found (configurable)
  const failOn = process.env.MYTHOH_FAIL_ON || "none";
  if (failOn !== "none") {
    const severityOrder = ["critical", "high", "medium", "low"];
    const threshold = severityOrder.indexOf(failOn);
    const failing = relevantFindings.filter(
      (f) => severityOrder.indexOf(f.severity) <= threshold
    );
    if (failing.length > 0) {
      console.error(
        `sphinx-agent: ${failing.length} findings at ${failOn} or above — failing`
      );
      process.exit(1);
    }
  }
}

function formatComment(finding: ScanFinding): string {
  const emoji = SEVERITY_EMOJI[finding.severity] || "⚪";
  const cwe = finding.cwe ? ` ([${finding.cwe}](https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html))` : "";

  return `${emoji} **sphinx-agent: ${finding.title}**${cwe}

${finding.description}

<details>
<summary>Details</summary>

- **Severity:** ${finding.severity}
- **Rule:** \`${finding.rule}\`
${finding.snippet ? `- **Code:** \`${finding.snippet}\`` : ""}
</details>`;
}

function buildSummaryComment(
  allFindings: ScanFinding[],
  prFindings: ScanFinding[],
  changedFilesCount: number
): string {
  const counts = {
    critical: prFindings.filter((f) => f.severity === "critical").length,
    high: prFindings.filter((f) => f.severity === "high").length,
    medium: prFindings.filter((f) => f.severity === "medium").length,
    low: prFindings.filter((f) => f.severity === "low").length,
  };

  const total = prFindings.length;

  if (total === 0) {
    return `## 🔐 sphinx-agent Security Scan

✅ **No security issues found** in ${changedFilesCount} changed files.

<sub>Powered by [sphinx-agent](https://github.com/sphinx-agent/sphinx-agent) — Agentic AI Security Scanner</sub>`;
  }

  const parts: string[] = [];
  if (counts.critical > 0) parts.push(`🔴 ${counts.critical} Critical`);
  if (counts.high > 0) parts.push(`🟠 ${counts.high} High`);
  if (counts.medium > 0) parts.push(`🟡 ${counts.medium} Medium`);
  if (counts.low > 0) parts.push(`🔵 ${counts.low} Low`);

  let score = 10;
  for (const f of prFindings) {
    switch (f.severity) {
      case "critical": score -= 2; break;
      case "high": score -= 1; break;
      case "medium": score -= 0.5; break;
      case "low": score -= 0.2; break;
    }
  }
  score = Math.max(0, Math.min(10, score));

  return `## 🔐 sphinx-agent Security Scan

**${total} issue${total !== 1 ? "s" : ""} found** in ${changedFilesCount} changed files

${parts.join(" &nbsp;|&nbsp; ")}

**Trust Score: ${score.toFixed(1)}/10** ${score >= 8 ? "✅" : score >= 5 ? "⚠️" : "❌"}

| # | Severity | File | Finding |
|---|----------|------|---------|
${prFindings
  .slice(0, 20)
  .map(
    (f, i) =>
      `| ${i + 1} | ${SEVERITY_EMOJI[f.severity]} ${f.severity} | \`${f.file}:${f.line}\` | ${f.title} |`
  )
  .join("\n")}
${total > 20 ? `\n*...and ${total - 20} more*` : ""}

<details>
<summary>How to fix</summary>

Run \`sphinx-agent fix --apply\` to auto-generate AI patches, or review each finding inline above.

</details>

<sub>Powered by [sphinx-agent](https://github.com/sphinx-agent/sphinx-agent) — Agentic AI Security Scanner</sub>`;
}

async function githubApi(
  endpoint: string,
  token: string,
  body: Record<string, unknown>
): Promise<void> {
  const response = await fetch(`https://api.github.com/${endpoint}`, {
    method: "POST",
    headers: {
      Authorization: `token ${token}`,
      "Content-Type": "application/json",
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "sphinx-agent-bot",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();
    console.error(`GitHub API error (${response.status}): ${text}`);
  }
}

main().catch((err) => {
  console.error("sphinx-agent bot error:", err);
  process.exit(1);
});
