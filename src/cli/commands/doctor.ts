import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { loadConfig } from "../../config/config.js";
import { checkAllTools } from "../../tools/index.js";
import { findConfigFile } from "../../config/config.js";
import { discoverLockfiles } from "../../scanner/lockfile-parsers.js";

interface DoctorOptions {
  path?: string;
}

export async function doctorCommand(options: DoctorOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);

  console.log(chalk.bold("\n🩺 sphinx-agent doctor\n"));
  console.log(chalk.dim("━".repeat(50)));

  let score = 0;
  let maxScore = 0;

  // 1. Config file
  maxScore += 1;
  const configFile = findConfigFile(projectPath);
  if (configFile) {
    score += 1;
    console.log(chalk.green("  ✓ Config file found:") + chalk.dim(` ${configFile}`));
  } else {
    console.log(chalk.yellow("  ✗ No .sphinx.yml config file") + chalk.dim(" — run: sphinx-agent init"));
  }

  // 2. API key
  maxScore += 1;
  if (config.apiKey && config.apiKey !== "not-needed") {
    score += 1;
    console.log(chalk.green("  ✓ API key configured") + chalk.dim(` (${config.provider})`));

    // Test the API key
    maxScore += 1;
    try {
      const testResponse = await fetch(
        config.provider === "anthropic"
          ? "https://api.anthropic.com/v1/messages"
          : "https://api.openai.com/v1/models",
        {
          method: config.provider === "anthropic" ? "POST" : "GET",
          headers: {
            "Content-Type": "application/json",
            ...(config.provider === "anthropic"
              ? { "x-api-key": config.apiKey, "anthropic-version": "2023-06-01" }
              : { Authorization: `Bearer ${config.apiKey}` }),
          },
          body: config.provider === "anthropic"
            ? JSON.stringify({ model: config.model, max_tokens: 1, messages: [{ role: "user", content: "hi" }] })
            : undefined,
        }
      );
      if (testResponse.status === 200 || testResponse.status === 401) {
        // 401 means key format is right but might be expired/invalid
        if (testResponse.ok) {
          score += 1;
          console.log(chalk.green("  ✓ API key valid") + chalk.dim(` (model: ${config.model})`));
        } else {
          console.log(chalk.yellow("  ✗ API key may be invalid") + chalk.dim(" — check your key"));
        }
      }
    } catch {
      console.log(chalk.yellow("  ✗ Could not verify API key") + chalk.dim(" — network error"));
    }
  } else {
    console.log(chalk.yellow("  ✗ No API key configured") + chalk.dim(" — AI features disabled. Run: sphinx-agent init"));
  }

  // 3. External tools
  console.log(chalk.dim("\n  External tools:"));
  const tools = checkAllTools();
  const installedTools = tools.filter((t) => t.installed);
  maxScore += 3; // up to 3 points for tools
  if (installedTools.length >= 4) score += 3;
  else if (installedTools.length >= 2) score += 2;
  else if (installedTools.length >= 1) score += 1;

  for (const tool of tools) {
    if (tool.installed) {
      console.log(chalk.green(`    ✓ ${tool.name}`) + chalk.dim(` ${tool.version || ""}`));
    } else {
      console.log(chalk.dim(`    ✗ ${tool.name} — not installed`));
    }
  }

  // 4. .gitignore includes .sphinx
  maxScore += 1;
  const gitignorePath = path.join(projectPath, ".gitignore");
  if (fs.existsSync(gitignorePath)) {
    const gitignore = fs.readFileSync(gitignorePath, "utf-8");
    if (gitignore.includes(".sphinx")) {
      score += 1;
      console.log(chalk.green("\n  ✓ .sphinx/ in .gitignore"));
    } else {
      console.log(chalk.yellow("\n  ✗ .sphinx/ not in .gitignore") + chalk.dim(" — scan results may be committed"));
    }
  } else {
    console.log(chalk.yellow("\n  ✗ No .gitignore file"));
  }

  // 5. Lockfiles present (for SCA scanning)
  maxScore += 1;
  const lockfiles = discoverLockfiles(projectPath);
  if (lockfiles.length > 0) {
    score += 1;
    console.log(chalk.green("  ✓ Lockfiles found:") + chalk.dim(` ${lockfiles.map((f) => path.basename(f)).join(", ")}`));
  } else {
    console.log(chalk.dim("  ✗ No lockfiles found — dependency scanning unavailable"));
  }

  // 6. Policy file
  maxScore += 1;
  const policyPath = path.join(projectPath, ".sphinx", "policy.yml");
  if (fs.existsSync(policyPath)) {
    score += 1;
    console.log(chalk.green("  ✓ Policy file configured"));
  } else {
    console.log(chalk.dim("  ✗ No policy file") + chalk.dim(" — run: sphinx-agent policy init"));
  }

  // 7. IaC files
  const hasDocker = fs.existsSync(path.join(projectPath, "Dockerfile")) ||
    fs.existsSync(path.join(projectPath, "docker-compose.yml"));
  const hasTerraform = fs.readdirSync(projectPath).some((f) => f.endsWith(".tf"));
  if (hasDocker || hasTerraform) {
    console.log(chalk.green("  ✓ IaC files detected:") +
      chalk.dim(` ${[hasDocker ? "Docker" : "", hasTerraform ? "Terraform" : ""].filter(Boolean).join(", ")}`));
  }

  // Summary
  const pct = Math.round((score / maxScore) * 100);
  const grade = pct >= 90 ? "A" : pct >= 75 ? "B" : pct >= 60 ? "C" : pct >= 40 ? "D" : "F";
  const gradeColor = pct >= 75 ? chalk.green : pct >= 50 ? chalk.yellow : chalk.red;

  console.log("\n" + chalk.dim("━".repeat(50)));
  console.log(
    chalk.bold(`\n  Security Setup Score: `) +
      gradeColor.bold(`${grade} (${pct}%)`) +
      chalk.dim(` — ${score}/${maxScore} checks passed`)
  );

  // Recommendations
  const recommendations: string[] = [];
  if (!configFile) recommendations.push("Run `sphinx-agent init` to create config");
  if (!config.apiKey) recommendations.push("Add API key for AI-powered analysis");
  if (installedTools.length < 2) recommendations.push("Install Semgrep + Trivy for deeper scanning");
  if (!fs.existsSync(policyPath)) recommendations.push("Run `sphinx-agent policy init` to enforce standards");

  if (recommendations.length > 0) {
    console.log(chalk.bold("\n  Recommendations:\n"));
    for (const r of recommendations) {
      console.log(chalk.dim(`    → ${r}`));
    }
  }

  console.log();
}
