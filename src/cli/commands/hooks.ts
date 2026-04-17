import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import chalk from "chalk";

const PRE_COMMIT_HOOK = `#!/bin/sh
# sphinx-agent pre-commit hook
# Scans staged files for security vulnerabilities before allowing commit

echo "🔐 sphinx-agent: scanning staged changes..."

# Run sphinx-agent on staged files only
npx sphinx-agent scan . --diff --no-ai --no-chain --no-deps --severity critical 2>/dev/null

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ sphinx-agent found critical security issues."
  echo "   Fix them before committing, or bypass with: git commit --no-verify"
  echo ""
  exit 1
fi

echo "✅ sphinx-agent: no critical issues found."
`;

const PRE_PUSH_HOOK = `#!/bin/sh
# sphinx-agent pre-push hook
# Full security scan before pushing

echo "🔐 sphinx-agent: running security scan before push..."

npx sphinx-agent ci --fail-on high 2>/dev/null

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ sphinx-agent found high/critical security issues."
  echo "   Fix them before pushing, or bypass with: git push --no-verify"
  echo ""
  exit 1
fi

echo "✅ sphinx-agent: security check passed."
`;

export async function hooksInstallCommand(options: {
  path?: string;
  preCommit?: boolean;
  prePush?: boolean;
}) {
  const projectPath = path.resolve(options.path || ".");
  const gitDir = path.join(projectPath, ".git");

  if (!fs.existsSync(gitDir)) {
    console.log(chalk.yellow("\n⚠️  Not a git repository.\n"));
    return;
  }

  const hooksDir = path.join(gitDir, "hooks");
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const installBoth = !options.preCommit && !options.prePush;
  let installed = 0;

  if (installBoth || options.preCommit) {
    const hookPath = path.join(hooksDir, "pre-commit");
    fs.writeFileSync(hookPath, PRE_COMMIT_HOOK, { mode: 0o755 });
    console.log(chalk.green(`  ✅ Installed pre-commit hook`));
    installed++;
  }

  if (installBoth || options.prePush) {
    const hookPath = path.join(hooksDir, "pre-push");
    fs.writeFileSync(hookPath, PRE_PUSH_HOOK, { mode: 0o755 });
    console.log(chalk.green(`  ✅ Installed pre-push hook`));
    installed++;
  }

  console.log(chalk.dim(`\n  ${installed} hook(s) installed to ${hooksDir}`));
  console.log(chalk.dim("  Bypass with --no-verify when needed.\n"));
}

export async function hooksUninstallCommand(options: { path?: string }) {
  const projectPath = path.resolve(options.path || ".");
  const hooksDir = path.join(projectPath, ".git", "hooks");

  let removed = 0;
  for (const hook of ["pre-commit", "pre-push"]) {
    const hookPath = path.join(hooksDir, hook);
    if (fs.existsSync(hookPath)) {
      const content = fs.readFileSync(hookPath, "utf-8");
      if (content.includes("sphinx-agent")) {
        fs.unlinkSync(hookPath);
        console.log(chalk.dim(`  Removed ${hook} hook`));
        removed++;
      }
    }
  }

  if (removed === 0) {
    console.log(chalk.dim("\n  No sphinx-agent hooks found.\n"));
  } else {
    console.log(chalk.green(`\n  ✅ ${removed} hook(s) removed.\n`));
  }
}
