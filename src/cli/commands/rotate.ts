import path from "node:path";
import crypto from "node:crypto";
import chalk from "chalk";
import { loadResults } from "../../store/results-store.js";
import type { Vulnerability } from "../../types/index.js";

interface RotateOptions {
  path?: string;
  json?: boolean;
}

interface RotationGuide {
  secretId: string;
  secretType: string;
  file: string;
  line: number;
  currentPattern: string;
  steps: string[];
  newValueExample: string;
  envVarName: string;
}

const SECRET_ROTATION_GUIDES: Record<
  string,
  {
    steps: string[];
    envVar: string;
    generate: () => string;
  }
> = {
  "secret:aws-access-key": {
    steps: [
      "Go to AWS IAM Console → Users → Security credentials",
      "Create new access key",
      "Update all services using the old key",
      "Deactivate the old key, then delete after 24h",
    ],
    envVar: "AWS_ACCESS_KEY_ID",
    generate: () => `AKIA${crypto.randomBytes(8).toString("hex").toUpperCase()}`,
  },
  "secret:github-pat": {
    steps: [
      "Go to GitHub → Settings → Developer settings → Personal access tokens",
      "Generate new token with same permissions",
      "Update CI/CD secrets and local .env files",
      "Delete the old token",
    ],
    envVar: "GITHUB_TOKEN",
    generate: () => `ghp_${crypto.randomBytes(18).toString("base64url")}`,
  },
  "secret:anthropic-key": {
    steps: [
      "Go to console.anthropic.com → API Keys",
      "Create new key",
      "Update .sphinx.yml and CI secrets",
      "Delete the old key",
    ],
    envVar: "SPHINX_API_KEY",
    generate: () => `sk-ant-api03-${crypto.randomBytes(46).toString("base64url")}`,
  },
  "secret:stripe-key": {
    steps: [
      "Go to Stripe Dashboard → Developers → API keys",
      "Roll the secret key (Stripe provides rolling)",
      "Update server environment variables",
      "The old key becomes invalid automatically",
    ],
    envVar: "STRIPE_SECRET_KEY",
    generate: () => `sk_live_${crypto.randomBytes(24).toString("base64url")}`,
  },
  "secret:database-url": {
    steps: [
      "Generate a new strong password",
      "Update the database user password",
      "Update all connection strings in environment variables",
      "Restart application services",
      "Verify connectivity",
    ],
    envVar: "DATABASE_URL",
    generate: () => `postgres://user:${crypto.randomBytes(16).toString("base64url")}@host:5432/db`,
  },
  "secret:generic-api-key": {
    steps: [
      "Generate a new API key from the provider's dashboard",
      "Update the key in your environment variables",
      "Remove the hardcoded value from source code",
      "Revoke the old key",
    ],
    envVar: "API_KEY",
    generate: () => crypto.randomBytes(32).toString("hex"),
  },
  "secret:private-key": {
    steps: [
      "Generate a new key pair: ssh-keygen -t ed25519 or openssl genrsa",
      "Update the public key wherever it's registered",
      "Replace the private key in your secrets manager",
      "Never commit private keys to git",
    ],
    envVar: "PRIVATE_KEY",
    generate: () => "(generate with: ssh-keygen -t ed25519)",
  },
};

export async function rotateCommand(options: RotateOptions) {
  const projectPath = path.resolve(options.path || ".");
  const result = loadResults(projectPath);

  if (!result) {
    console.log(chalk.yellow("\n⚠️  No scan results. Run mythos-agent scan first.\n"));
    return;
  }

  const secrets = result.confirmedVulnerabilities.filter((v) => v.category === "secrets");

  if (secrets.length === 0) {
    console.log(chalk.green("\n✅ No hardcoded secrets found!\n"));
    return;
  }

  const guides = secrets.map((s) => buildRotationGuide(s));

  if (options.json) {
    console.log(JSON.stringify(guides, null, 2));
    return;
  }

  console.log(chalk.bold("\n🔄 mythos-agent rotate — Secret Rotation Guide\n"));
  console.log(chalk.dim("━".repeat(50)));
  console.log(chalk.dim(`\n  ${secrets.length} secret(s) need rotation:\n`));

  for (const guide of guides) {
    console.log(chalk.red.bold(`  ${guide.secretId} — ${guide.secretType}`));
    console.log(chalk.dim(`    File: ${guide.file}:${guide.line}`));
    console.log(chalk.dim(`    Pattern: ${guide.currentPattern}`));
    console.log();

    console.log(chalk.bold("    Steps:"));
    for (let i = 0; i < guide.steps.length; i++) {
      console.log(chalk.dim(`      ${i + 1}. ${guide.steps[i]}`));
    }
    console.log();

    console.log(chalk.dim("    Replace with environment variable:"));
    console.log(chalk.cyan(`      ${guide.envVarName}=${guide.newValueExample}`));
    console.log();
    console.log(chalk.dim("    " + "─".repeat(44)));
    console.log();
  }

  console.log(chalk.bold("  Summary:\n"));
  console.log(chalk.dim("    1. Rotate all secrets following the steps above"));
  console.log(chalk.dim("    2. Store new values in environment variables or a secrets manager"));
  console.log(chalk.dim("    3. Remove hardcoded values from source code"));
  console.log(
    chalk.dim("    4. Run ") + chalk.cyan("mythos-agent scan") + chalk.dim(" again to verify\n")
  );
}

function buildRotationGuide(vuln: Vulnerability): RotationGuide {
  const ruleBase = vuln.rule.replace("secret:", "").replace("gitleaks:", "");

  // Find matching guide
  let guide = SECRET_ROTATION_GUIDES[vuln.rule];
  if (!guide) {
    // Try to match by pattern in rule name
    for (const [key, g] of Object.entries(SECRET_ROTATION_GUIDES)) {
      if (ruleBase.includes(key.replace("secret:", ""))) {
        guide = g;
        break;
      }
    }
  }

  // Fallback
  if (!guide) {
    guide = SECRET_ROTATION_GUIDES["secret:generic-api-key"];
  }

  return {
    secretId: vuln.id,
    secretType: vuln.title,
    file: vuln.location.file,
    line: vuln.location.line,
    currentPattern: vuln.location.snippet || "",
    steps: guide.steps,
    newValueExample: guide.generate(),
    envVarName: guide.envVar,
  };
}
