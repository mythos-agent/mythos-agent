import path from "node:path";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";
import type { ScanResult, Vulnerability } from "../../types/index.js";

interface NotifyOptions {
  path?: string;
  slack?: string;
  discord?: string;
  teams?: string;
  webhook?: string;
}

export async function notifyCommand(options: NotifyOptions) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(chalk.yellow("\n⚠️  No scan results. Run mythos-agent scan first.\n"));
    return;
  }

  let sent = 0;

  if (options.slack) {
    await sendSlack(options.slack, result);
    sent++;
  }
  if (options.discord) {
    await sendDiscord(options.discord, result);
    sent++;
  }
  if (options.teams) {
    await sendTeams(options.teams, result);
    sent++;
  }
  if (options.webhook) {
    await sendWebhook(options.webhook, result);
    sent++;
  }

  if (sent === 0) {
    console.log(
      chalk.yellow("\n⚠️  Specify a webhook: --slack, --discord, --teams, or --webhook <url>\n")
    );
    return;
  }

  console.log(chalk.green(`\n  ✅ Sent notifications to ${sent} channel(s)\n`));
}

async function sendSlack(webhookUrl: string, result: ScanResult): Promise<void> {
  const vulns = result.confirmedVulnerabilities;
  const counts = countBySeverity(vulns);
  const trustScore = calcTrustScore(vulns);
  const project = path.basename(result.projectPath);

  const blocks = [
    {
      type: "header",
      text: { type: "plain_text", text: `🔐 mythos-agent: ${project}` },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text:
          `*Trust Score: ${trustScore.toFixed(1)}/10* ${trustScore >= 7 ? "✅" : trustScore >= 4 ? "⚠️" : "❌"}\n\n` +
          `🔴 ${counts.critical} Critical  🟠 ${counts.high} High  🟡 ${counts.medium} Medium  🔵 ${counts.low} Low\n` +
          `⛓️ ${result.chains.length} Attack Chain(s)`,
      },
    },
  ];

  // Add top findings
  const top = vulns.filter((v) => v.severity === "critical" || v.severity === "high").slice(0, 5);
  if (top.length > 0) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text:
          "*Top findings:*\n" +
          top.map((v) => `• \`${v.location.file}:${v.location.line}\` ${v.title}`).join("\n"),
      },
    });
  }

  await postJson(webhookUrl, { blocks });
}

async function sendDiscord(webhookUrl: string, result: ScanResult): Promise<void> {
  const vulns = result.confirmedVulnerabilities;
  const counts = countBySeverity(vulns);
  const trustScore = calcTrustScore(vulns);
  const project = path.basename(result.projectPath);

  const embed = {
    title: `🔐 mythos-agent: ${project}`,
    color: trustScore >= 7 ? 0x22c55e : trustScore >= 4 ? 0xeab308 : 0xef4444,
    fields: [
      { name: "Trust Score", value: `${trustScore.toFixed(1)}/10`, inline: true },
      { name: "Findings", value: `${vulns.length}`, inline: true },
      { name: "Chains", value: `${result.chains.length}`, inline: true },
      {
        name: "Breakdown",
        value: `🔴 ${counts.critical} | 🟠 ${counts.high} | 🟡 ${counts.medium} | 🔵 ${counts.low}`,
      },
    ],
    footer: { text: "mythos-agent — AI security agent" },
    timestamp: result.timestamp,
  };

  await postJson(webhookUrl, { embeds: [embed] });
}

async function sendTeams(webhookUrl: string, result: ScanResult): Promise<void> {
  const vulns = result.confirmedVulnerabilities;
  const counts = countBySeverity(vulns);
  const trustScore = calcTrustScore(vulns);
  const project = path.basename(result.projectPath);

  const card = {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor: trustScore >= 7 ? "22c55e" : trustScore >= 4 ? "eab308" : "ef4444",
    summary: `mythos-agent: ${vulns.length} findings in ${project}`,
    title: `🔐 mythos-agent: ${project}`,
    text:
      `**Trust Score: ${trustScore.toFixed(1)}/10**\n\n` +
      `🔴 ${counts.critical} Critical | 🟠 ${counts.high} High | 🟡 ${counts.medium} Medium | 🔵 ${counts.low} Low\n\n` +
      `⛓️ ${result.chains.length} Attack Chain(s)`,
  };

  await postJson(webhookUrl, card);
}

async function sendWebhook(webhookUrl: string, result: ScanResult): Promise<void> {
  const vulns = result.confirmedVulnerabilities;
  await postJson(webhookUrl, {
    source: "mythos-agent",
    project: path.basename(result.projectPath),
    timestamp: result.timestamp,
    trustScore: calcTrustScore(vulns),
    findings: vulns.length,
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
    chains: result.chains.length,
  });
}

/**
 * Reject URLs that target loopback, link-local, private, or cloud-metadata
 * addresses. Prevents SSRF via user-supplied --webhook / --slack / --discord
 * / --teams flags.
 */
export function assertPublicWebhookUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`Invalid webhook URL: ${raw}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`Webhook URL must use http(s): ${url.protocol}`);
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  // Explicit localhost / metadata hostnames
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "metadata.google.internal" ||
    host === "metadata" ||
    host === "metadata.azure.com"
  ) {
    throw new Error(`Webhook URL cannot target internal host: ${host}`);
  }

  // IPv4 literal
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    const blocked =
      a === 0 || // 0.0.0.0/8
      a === 10 || // private
      a === 127 || // loopback
      (a === 169 && b === 254) || // link-local (AWS/GCP metadata 169.254.169.254)
      (a === 172 && b >= 16 && b <= 31) || // private
      (a === 192 && b === 168) || // private
      a >= 224; // multicast + reserved
    if (blocked) {
      throw new Error(`Webhook URL cannot target private/metadata IP: ${host}`);
    }
  }

  // IPv6 literal — loopback, link-local, unique-local
  if (host.includes(":")) {
    if (
      host === "::" ||
      host === "::1" ||
      host.startsWith("fe80:") ||
      host.startsWith("fc") ||
      host.startsWith("fd")
    ) {
      throw new Error(`Webhook URL cannot target private/loopback IPv6: ${host}`);
    }
  }

  return url;
}

async function postJson(rawUrl: string, body: unknown): Promise<void> {
  let url: URL;
  try {
    url = assertPublicWebhookUrl(rawUrl);
  } catch (err) {
    console.log(
      chalk.red(`  Refused webhook: ${err instanceof Error ? err.message : String(err)}`)
    );
    return;
  }
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (err) {
    console.log(
      chalk.red(`  Failed to send to ${url}: ${err instanceof Error ? err.message : "error"}`)
    );
  }
}

function countBySeverity(vulns: Vulnerability[]) {
  return {
    critical: vulns.filter((v) => v.severity === "critical").length,
    high: vulns.filter((v) => v.severity === "high").length,
    medium: vulns.filter((v) => v.severity === "medium").length,
    low: vulns.filter((v) => v.severity === "low").length,
  };
}

function calcTrustScore(vulns: Vulnerability[]): number {
  let score = 10;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        score -= 2;
        break;
      case "high":
        score -= 1;
        break;
      case "medium":
        score -= 0.5;
        break;
      case "low":
        score -= 0.2;
        break;
    }
  }
  return Math.max(0, Math.min(10, score));
}
