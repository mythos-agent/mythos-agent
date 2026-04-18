import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { glob } from "glob";
import { writeConfig } from "../../config/config.js";
import { getPreset, PRESETS } from "../../config/presets.js";
import { generateDefaultPolicy } from "../../policy/engine.js";

interface GenerateOptions {
  path?: string;
  force?: boolean;
}

interface DetectedStack {
  framework: string;
  preset: string;
  confidence: number;
  indicators: string[];
}

export async function generateCommand(options: GenerateOptions) {
  const projectPath = path.resolve(options.path || ".");

  console.log(chalk.bold("\n🔧 mythos-agent generate — Auto-configure\n"));

  // Detect project type
  const detected = await detectProjectType(projectPath);

  if (detected.length === 0) {
    console.log(chalk.yellow("  Could not detect project type. Using fullstack preset.\n"));
    detected.push({
      framework: "Full Stack",
      preset: "fullstack",
      confidence: 50,
      indicators: ["fallback"],
    });
  }

  const best = detected[0];
  console.log(
    chalk.green(`  Detected: ${best.framework}`) + chalk.dim(` (${best.confidence}% confidence)`)
  );
  console.log(chalk.dim(`  Indicators: ${best.indicators.join(", ")}\n`));

  // Generate .sphinx.yml
  const configPath = path.join(projectPath, ".sphinx.yml");
  if (!fs.existsSync(configPath) || options.force) {
    const preset = getPreset(best.preset);
    if (preset) {
      writeConfig(projectPath, {
        model: "claude-sonnet-4-20250514",
        provider: "anthropic",
        ...preset.config,
      } as any);
      console.log(chalk.green(`  ✅ Created .sphinx.yml`) + chalk.dim(` (${best.preset} preset)`));
    }
  } else {
    console.log(chalk.dim("  ⏭  .sphinx.yml already exists (use --force to overwrite)"));
  }

  // Generate policy
  const policyPath = path.join(projectPath, ".sphinx", "policy.yml");
  if (!fs.existsSync(policyPath) || options.force) {
    const policyDir = path.dirname(policyPath);
    if (!fs.existsSync(policyDir)) fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(policyPath, generateDefaultPolicy(), "utf-8");
    console.log(chalk.green("  ✅ Created .sphinx/policy.yml"));
  } else {
    console.log(chalk.dim("  ⏭  policy.yml already exists"));
  }

  // Generate .sphinxignore
  const ignorePath = path.join(projectPath, ".sphinxignore");
  if (!fs.existsSync(ignorePath) || options.force) {
    const ignoreContent = generateIgnoreFile(best.preset);
    fs.writeFileSync(ignorePath, ignoreContent, "utf-8");
    console.log(chalk.green("  ✅ Created .sphinxignore"));
  } else {
    console.log(chalk.dim("  ⏭  .sphinxignore already exists"));
  }

  // Update .gitignore
  const gitignorePath = path.join(projectPath, ".gitignore");
  if (fs.existsSync(gitignorePath)) {
    let gitignore = fs.readFileSync(gitignorePath, "utf-8");
    let added = false;
    for (const entry of [".sphinx/", ".sphinx.yml"]) {
      if (!gitignore.includes(entry)) {
        gitignore += `\n${entry}`;
        added = true;
      }
    }
    if (added) {
      fs.writeFileSync(gitignorePath, gitignore);
      console.log(chalk.green("  ✅ Updated .gitignore"));
    }
  }

  console.log(chalk.bold("\n  Next steps:\n"));
  console.log(
    chalk.dim("    1. ") + chalk.cyan("mythos-agent init") + chalk.dim(" — add your API key")
  );
  console.log(
    chalk.dim("    2. ") + chalk.cyan("mythos-agent scan") + chalk.dim(" — run your first scan")
  );
  console.log(
    chalk.dim("    3. ") + chalk.cyan("mythos-agent hooks install") + chalk.dim(" — add git hooks")
  );
  console.log();
}

async function detectProjectType(projectPath: string): Promise<DetectedStack[]> {
  const detected: DetectedStack[] = [];
  const files = fs.readdirSync(projectPath);
  const hasFile = (name: string) => files.includes(name);

  // Next.js
  if (hasFile("next.config.js") || hasFile("next.config.ts") || hasFile("next.config.mjs")) {
    detected.push({
      framework: "Next.js",
      preset: "nextjs",
      confidence: 95,
      indicators: ["next.config.*"],
    });
  }

  // Express
  const hasPkg = hasFile("package.json");
  if (hasPkg) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(projectPath, "package.json"), "utf-8"));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (allDeps.express) {
        detected.push({
          framework: "Express.js",
          preset: "express",
          confidence: 90,
          indicators: ["express in dependencies"],
        });
      }
      if (allDeps.react && !allDeps.next) {
        detected.push({
          framework: "React",
          preset: "react",
          confidence: 85,
          indicators: ["react in dependencies"],
        });
      }
    } catch {
      /* ignore */
    }
  }

  // Django
  if (hasFile("manage.py") || hasFile("settings.py")) {
    detected.push({
      framework: "Django",
      preset: "django",
      confidence: 90,
      indicators: ["manage.py or settings.py"],
    });
  }

  // Flask
  if (hasFile("app.py") || hasFile("wsgi.py")) {
    const appContent = hasFile("app.py")
      ? fs.readFileSync(path.join(projectPath, "app.py"), "utf-8")
      : "";
    if (appContent.includes("Flask") || appContent.includes("flask")) {
      detected.push({
        framework: "Flask",
        preset: "flask",
        confidence: 85,
        indicators: ["Flask import in app.py"],
      });
    }
  }

  // Spring Boot
  if (hasFile("pom.xml") || hasFile("build.gradle") || hasFile("build.gradle.kts")) {
    detected.push({
      framework: "Spring Boot",
      preset: "spring",
      confidence: 80,
      indicators: ["pom.xml or build.gradle"],
    });
  }

  // Go
  if (hasFile("go.mod")) {
    detected.push({
      framework: "Go",
      preset: "go",
      confidence: 90,
      indicators: ["go.mod"],
    });
  }

  // Sort by confidence
  detected.sort((a, b) => b.confidence - a.confidence);
  return detected;
}

function generateIgnoreFile(preset: string): string {
  let content = `# mythos-agent ignore rules
# Suppress findings matching these patterns

# Ignore test files (usually false positives)
# severity:info

# Example: ignore a specific rule everywhere
# rule:express-no-helmet

# Example: ignore a file pattern
# test/**
# __mocks__/**
`;

  switch (preset) {
    case "express":
    case "nextjs":
    case "react":
      content += `\n# Common JS/TS test patterns\n# **/*.test.ts\n# **/*.spec.ts\n# **/__tests__/**\n`;
      break;
    case "django":
    case "flask":
      content += `\n# Common Python test patterns\n# tests/**\n# test_*.py\n`;
      break;
    case "spring":
      content += `\n# Common Java test patterns\n# **/test/**\n# **/*Test.java\n`;
      break;
  }

  return content;
}
