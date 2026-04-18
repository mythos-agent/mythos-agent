import chalk from "chalk";

interface CompletionOptions {
  shell: string;
}

export async function completionCommand(options: CompletionOptions) {
  const commands = [
    "scan",
    "hunt",
    "pentest",
    "ci",
    "taint",
    "watch",
    "variants",
    "history",
    "fix",
    "ask",
    "plan",
    "threat-model",
    "report",
    "dashboard",
    "map",
    "sbom",
    "compliance",
    "score",
    "deps",
    "summary",
    "benchmark",
    "diff-report",
    "changelog",
    "export",
    "init",
    "generate",
    "doctor",
    "tools",
    "rules",
    "policy",
    "baseline",
    "suppress",
    "hooks",
    "compare",
    "license",
    "rotate",
    "stats",
    "notify",
    "serve",
    "mcp",
    "image",
    "monitor",
    "import",
    "completion",
  ];

  switch (options.shell) {
    case "bash":
      console.log(generateBash(commands));
      break;
    case "zsh":
      console.log(generateZsh(commands));
      break;
    case "fish":
      console.log(generateFish(commands));
      break;
    default:
      console.log(chalk.bold("\n  Shell Completions\n"));
      console.log(chalk.dim("  Add to your shell config:\n"));
      console.log(chalk.cyan("  # Bash (~/.bashrc)"));
      console.log(chalk.dim('  eval "$(mythos-agent completion --shell bash)"\n'));
      console.log(chalk.cyan("  # Zsh (~/.zshrc)"));
      console.log(chalk.dim('  eval "$(mythos-agent completion --shell zsh)"\n'));
      console.log(chalk.cyan("  # Fish (~/.config/fish/config.fish)"));
      console.log(chalk.dim("  mythos-agent completion --shell fish | source\n"));
  }
}

function generateBash(commands: string[]): string {
  return `# mythos-agent bash completion
_sphinx_agent() {
  local cur=\${COMP_WORDS[COMP_CWORD]}
  COMPREPLY=( $(compgen -W "${commands.join(" ")}" -- "$cur") )
}
complete -F _sphinx_agent mythos-agent
complete -F _sphinx_agent npx\\ mythos-agent`;
}

function generateZsh(commands: string[]): string {
  return `# mythos-agent zsh completion
_sphinx_agent() {
  local -a commands
  commands=(${commands.map((c) => `'${c}'`).join(" ")})
  _describe 'command' commands
}
compdef _sphinx_agent mythos-agent`;
}

function generateFish(commands: string[]): string {
  return commands
    .map((c) => `complete -c mythos-agent -f -n "__fish_use_subcommand" -a "${c}"`)
    .join("\n");
}
