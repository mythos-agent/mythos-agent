import chalk from "chalk";
import { checkAllTools } from "../../tools/index.js";

export async function toolsCheckCommand() {
  console.log(chalk.bold("\n🔧 sphinx-agent tools\n"));

  const tools = checkAllTools();
  const maxName = Math.max(...tools.map((t) => t.name.length));

  for (const tool of tools) {
    const name = tool.name.padEnd(maxName + 2);
    if (tool.installed) {
      console.log(
        `  ${chalk.green("✓")} ${chalk.bold(name)} ${chalk.dim(tool.version || "installed")}`
      );
    } else {
      console.log(`  ${chalk.red("✗")} ${chalk.dim(name)} ${chalk.yellow("not installed")}`);
    }
  }

  const installed = tools.filter((t) => t.installed).length;
  const total = tools.length;

  console.log(chalk.dim(`\n  ${installed}/${total} tools available.`));

  if (installed < total) {
    console.log(chalk.dim("\n  sphinx-agent works without external tools (built-in rules)."));
    console.log(chalk.dim("  Install tools for deeper analysis:\n"));

    const missing = tools.filter((t) => !t.installed);
    for (const t of missing) {
      const installCmd = getInstallCommand(t.name);
      if (installCmd) {
        console.log(chalk.dim(`    ${t.name}: `) + chalk.cyan(installCmd));
      }
    }
    console.log();
  }
}

function getInstallCommand(name: string): string | null {
  const commands: Record<string, string> = {
    semgrep: "pip install semgrep",
    gitleaks: "brew install gitleaks  # or: go install github.com/gitleaks/gitleaks/v8@latest",
    trivy: "brew install trivy  # or: apt-get install trivy",
    checkov: "pip install checkov",
    nuclei: "go install github.com/projectdiscovery/nuclei/v3@latest",
    nmap: "apt-get install nmap  # or: brew install nmap",
    httpx: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    sqlmap: "pip install sqlmap",
  };
  return commands[name] || null;
}
