#!/usr/bin/env node

import { Command } from "commander";
import { scanCommand } from "./commands/scan.js";
import { initCommand } from "./commands/init.js";
import { reportCommand } from "./commands/report.js";
import { fixCommand } from "./commands/fix.js";
import { askCommand } from "./commands/ask.js";
import { watchCommand } from "./commands/watch.js";
import { taintCommand } from "./commands/taint.js";
import { policyCheckCommand, policyInitCommand } from "./commands/policy.js";
import { dashboardCommand } from "./commands/dashboard.js";
import { toolsCheckCommand } from "./commands/tools.js";
import { huntCommand } from "./commands/hunt.js";
import { variantsCommand } from "./commands/variants.js";
import { pentestCommand } from "./commands/pentest.js";
import { ciCommand } from "./commands/ci.js";
import { baselineSaveCommand, baselineCompareCommand } from "./commands/baseline.js";
import { doctorCommand } from "./commands/doctor.js";
import {
  rulesSearchCommand,
  rulesInstallCommand,
  rulesUninstallCommand,
  rulesListCommand,
  rulesInitCommand,
} from "./commands/rules.js";

const program = new Command();

program
  .name("sphinx-agent")
  .description(
    "Agentic AI security scanner — Mythos for everyone.\nFinds vulnerabilities, chains them into attack paths, and generates patches."
  )
  .version("1.0.0");

program
  .command("scan")
  .description("Scan a project for vulnerabilities")
  .argument("[path]", "Path to scan", ".")
  .option("--no-ai", "Skip AI analysis (pattern scan only)")
  .option("--no-chain", "Skip vulnerability chaining")
  .option(
    "-s, --severity <level>",
    "Minimum severity to report",
    "low"
  )
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .option("--json", "Output as JSON (shorthand for -o json)")
  .option("-r, --rules <path>", "Path to custom rules directory")
  .option("--diff [base]", "Only scan files changed in git (optionally vs a branch)")
  .option("--sarif", "Output as SARIF")
  .option("--no-secrets", "Skip secrets detection")
  .option("--no-deps", "Skip dependency vulnerability scanning")
  .option("--no-iac", "Skip infrastructure-as-code scanning")
  .action(scanCommand);

program
  .command("fix")
  .description("Generate AI-powered patches for vulnerabilities")
  .argument("[path]", "Path to the scanned project", ".")
  .option("--apply", "Automatically apply patches")
  .option("--dry-run", "Show patches without applying (default)")
  .option("-i, --id <ids...>", "Fix specific vulnerability IDs only")
  .option(
    "-s, --severity <level>",
    "Fix vulnerabilities at or above this severity",
    "low"
  )
  .action(fixCommand);

program
  .command("init")
  .description("Initialize sphinx-agent configuration")
  .action(initCommand);

program
  .command("ask")
  .description("Ask AI security questions about your codebase")
  .argument("[question]", "Security question (omit for interactive mode)")
  .option("-p, --path <path>", "Project path", ".")
  .option("-i, --interactive", "Force interactive mode")
  .action(askCommand);

program
  .command("watch")
  .description("Watch for file changes and scan continuously")
  .option("-p, --path <path>", "Project path", ".")
  .option(
    "-s, --severity <level>",
    "Minimum severity to report",
    "low"
  )
  .action(watchCommand);

program
  .command("taint")
  .description("AI-powered data flow / taint analysis")
  .argument("[path]", "Path to analyze", ".")
  .option("--json", "Output as JSON")
  .action(taintCommand);

program
  .command("dashboard")
  .description("Launch web dashboard for scan results")
  .option("-p, --path <path>", "Project path", ".")
  .option("--port <port>", "Port number", "4040")
  .action((options: { path: string; port: string }) => {
    dashboardCommand({ path: options.path, port: parseInt(options.port) });
  });

program
  .command("report")
  .description("Display or export the latest scan results")
  .argument("[path]", "Path to the scanned project", ".")
  .option("-o, --output <format>", "Output format: terminal, json, html, sarif", "terminal")
  .option("--json", "Output as JSON")
  .option("--html", "Output as HTML report")
  .option("--sarif", "Output as SARIF (GitHub Code Scanning)")
  .option("--md", "Output as Markdown report")
  .action((scanPath: string, options: Record<string, unknown>) => {
    reportCommand({ ...options, path: scanPath } as any);
  });

const policyCmd = program
  .command("policy")
  .description("Policy-as-code: enforce security standards");

policyCmd
  .command("check")
  .description("Check scan results against policy")
  .option("-p, --path <path>", "Project path", ".")
  .option("--json", "Output as JSON")
  .action(policyCheckCommand);

policyCmd
  .command("init")
  .description("Create a default policy file")
  .option("-p, --path <path>", "Project path", ".")
  .action(policyInitCommand);

const rulesCmd = program
  .command("rules")
  .description("Manage community rule packs");

rulesCmd
  .command("search")
  .description("Search for rule packs on npm")
  .argument("<query>", "Search query")
  .action(rulesSearchCommand);

rulesCmd
  .command("install")
  .description("Install a rule pack")
  .argument("<name>", "Rule pack name")
  .action(rulesInstallCommand);

rulesCmd
  .command("uninstall")
  .description("Uninstall a rule pack")
  .argument("<name>", "Rule pack name")
  .action(rulesUninstallCommand);

rulesCmd
  .command("list")
  .description("List installed rule packs")
  .action(rulesListCommand);

rulesCmd
  .command("init")
  .description("Scaffold a new rule pack for publishing")
  .argument("<name>", "Rule pack name")
  .action(rulesInitCommand);

program
  .command("hunt")
  .description("Autonomous multi-agent security hunt (Recon → Hypothesize → Analyze → Exploit)")
  .argument("[path]", "Path to scan", ".")
  .option("--json", "Output as JSON")
  .action(huntCommand);

program
  .command("variants")
  .description("Find variants of known CVEs in your codebase (Big Sleep technique)")
  .argument("[cve-id]", "CVE ID to search for variants of (e.g., CVE-2021-44228)")
  .option("-p, --path <path>", "Project path", ".")
  .option("--auto", "Auto-detect dependencies and scan for variants")
  .option("--json", "Output as JSON")
  .action(variantsCommand);

program
  .command("ci")
  .description("CI/CD mode: scan + policy check + SARIF output (one command for pipelines)")
  .option("-p, --path <path>", "Project path", ".")
  .option("--fail-on <severity>", "Fail if findings at this severity or above (critical, high, medium, low, none)", "none")
  .option("--sarif <path>", "Write SARIF output to file")
  .option("--json", "Output summary as JSON")
  .action(ciCommand);

program
  .command("pentest")
  .description("Dynamic security test against a live target URL")
  .argument("<url>", "Target URL (e.g., http://localhost:3000)")
  .option("-p, --path <path>", "Source code path for endpoint discovery", ".")
  .option("--no-smart", "Use payload library instead of AI-guided fuzzing")
  .option("--no-nuclei", "Skip Nuclei template scan")
  .option("--no-poc", "Skip PoC generation")
  .option("--json", "Output as JSON")
  .action(pentestCommand);

const baselineCmd = program
  .command("baseline")
  .description("Track findings over time — save and compare baselines");

baselineCmd
  .command("save")
  .description("Save current scan results as the baseline")
  .option("-p, --path <path>", "Project path", ".")
  .action(baselineSaveCommand);

baselineCmd
  .command("compare")
  .description("Compare current results against saved baseline")
  .option("-p, --path <path>", "Project path", ".")
  .option("--json", "Output as JSON")
  .action(baselineCompareCommand);

program
  .command("doctor")
  .description("Health check: verify config, tools, and project security setup")
  .option("-p, --path <path>", "Project path", ".")
  .action(doctorCommand);

program
  .command("tools")
  .description("Check which external security tools are installed")
  .action(toolsCheckCommand);

program.parse();
