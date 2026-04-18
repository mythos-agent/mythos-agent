import path from "node:path";
import { spawnSync } from "node:child_process";
import chalk from "chalk";
import ora from "ora";
import type { Vulnerability } from "../../types/index.js";

interface HistoryScanOptions {
  path?: string;
  depth: number;
  json?: boolean;
}

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: "critical" | "high" }> = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
  { name: "GitHub PAT", pattern: /ghp_[0-9a-zA-Z]{36}/g, severity: "critical" },
  { name: "GitHub OAuth", pattern: /gho_[0-9a-zA-Z]{36}/g, severity: "critical" },
  { name: "Anthropic API Key", pattern: /sk-ant-api03-[0-9a-zA-Z\-_]{20,}/g, severity: "critical" },
  {
    name: "OpenAI API Key",
    pattern: /sk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20}/g,
    severity: "critical",
  },
  { name: "Stripe Secret Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical" },
  { name: "Stripe Publishable", pattern: /pk_live_[0-9a-zA-Z]{24,}/g, severity: "high" },
  {
    name: "Slack Bot Token",
    pattern: /xoxb-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{24}/g,
    severity: "critical",
  },
  {
    name: "Slack Webhook",
    pattern:
      /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/g,
    severity: "high",
  },
  {
    name: "Private Key",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
  },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: "high" },
  { name: "npm Token", pattern: /npm_[0-9a-zA-Z]{36}/g, severity: "critical" },
  {
    name: "SendGrid Key",
    pattern: /SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}/g,
    severity: "high",
  },
  {
    name: "Database URL",
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s"'`]+/g,
    severity: "critical",
  },
  {
    name: "JWT Token",
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: "high",
  },
];

export async function historyScanCommand(options: HistoryScanOptions) {
  const projectPath = path.resolve(options.path || ".");

  console.log(chalk.bold("\n🕵️  mythos-agent history — Git History Secret Scan\n"));

  // Check if git repo
  const gitCheck = spawnSync("git", ["rev-parse", "--git-dir"], {
    cwd: projectPath,
    encoding: "utf-8",
    stdio: "pipe",
  });
  if (gitCheck.status !== 0) {
    console.log(chalk.yellow("  ⚠️  Not a git repository.\n"));
    return;
  }

  const spinner = ora(`Scanning last ${options.depth} commits for secrets...`).start();

  // Get commit hashes
  const logResult = spawnSync(
    "git",
    ["log", `--max-count=${options.depth}`, "--pretty=format:%H|%an|%ai|%s"],
    { cwd: projectPath, encoding: "utf-8", stdio: "pipe" }
  );

  if (!logResult.stdout) {
    spinner.warn("No commits found.");
    return;
  }

  const commits = logResult.stdout
    .trim()
    .split("\n")
    .map((line) => {
      const [hash, author, date, ...subject] = line.split("|");
      return { hash, author, date, subject: subject.join("|") };
    });

  const findings: Vulnerability[] = [];
  let idCounter = 1;
  let commitsScanned = 0;

  for (const commit of commits) {
    // Get diff for this commit
    const diffResult = spawnSync("git", ["diff-tree", "-p", commit.hash], {
      cwd: projectPath,
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: 10 * 1024 * 1024,
    });

    if (!diffResult.stdout) continue;
    commitsScanned++;

    const diffLines = diffResult.stdout.split("\n");
    let currentFile = "";

    for (let i = 0; i < diffLines.length; i++) {
      const line = diffLines[i];

      // Track current file
      if (line.startsWith("+++ b/")) {
        currentFile = line.slice(6);
        continue;
      }

      // Only check added lines
      if (!line.startsWith("+") || line.startsWith("+++")) continue;
      const addedLine = line.slice(1);

      for (const secret of SECRET_PATTERNS) {
        secret.pattern.lastIndex = 0;
        if (secret.pattern.test(addedLine)) {
          findings.push({
            id: `HIST-${String(idCounter++).padStart(4, "0")}`,
            rule: `history:${secret.name.toLowerCase().replace(/\s+/g, "-")}`,
            title: `Git History: ${secret.name} in commit ${commit.hash.slice(0, 8)}`,
            description: `A ${secret.name} was found in a historical commit. Even if removed from the current code, it's still in git history. Rotate this credential immediately and consider rewriting git history.`,
            severity: secret.severity,
            category: "secrets",
            cwe: "CWE-798",
            confidence: "high",
            location: {
              file: currentFile,
              line: 0,
              snippet: `Commit: ${commit.hash.slice(0, 8)} by ${commit.author} (${commit.date?.split(" ")[0]})`,
            },
          });
          break;
        }
      }
    }
  }

  spinner.stop();

  if (findings.length === 0) {
    console.log(chalk.green(`  ✅ No secrets found in last ${commitsScanned} commits.\n`));
    return;
  }

  if (options.json) {
    console.log(
      JSON.stringify({ commitsScanned, findings: findings.length, secrets: findings }, null, 2)
    );
    return;
  }

  console.log(chalk.red.bold(`  🚨 Found ${findings.length} secret(s) in git history!\n`));

  for (const f of findings) {
    const color = f.severity === "critical" ? chalk.red : chalk.yellow;
    console.log(`  ${color(`[${f.severity.toUpperCase()}]`)} ${f.title}`);
    console.log(chalk.dim(`    File: ${f.location.file}`));
    console.log(chalk.dim(`    ${f.location.snippet}`));
    console.log();
  }

  console.log(chalk.bold("  Remediation:\n"));
  console.log(chalk.dim("    1. Rotate ALL found credentials immediately"));
  console.log(chalk.dim("    2. Run: mythos-agent rotate — for rotation guides"));
  console.log(
    chalk.dim("    3. Consider: git filter-branch or BFG Repo-Cleaner to remove from history")
  );
  console.log(chalk.dim("    4. Force-push cleaned history (coordinate with team)\n"));
}
