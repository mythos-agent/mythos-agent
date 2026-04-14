export { runTool, checkTool, checkAllTools, type ToolInfo, type ToolResult } from "./tool-runner.js";
export { runSemgrep, isSemgrepInstalled } from "./semgrep.js";
export { runGitleaks, isGitleaksInstalled } from "./gitleaks.js";
export { runTrivyFs, runTrivyImage, isTrivyInstalled } from "./trivy.js";
export { runNuclei, isNucleiInstalled } from "./nuclei.js";
export { runCheckov, isCheckovInstalled } from "./checkov.js";

import type { Vulnerability } from "../types/index.js";
import { checkTool } from "./tool-runner.js";
import { runSemgrep } from "./semgrep.js";
import { runGitleaks } from "./gitleaks.js";
import { runTrivyFs } from "./trivy.js";
import { runCheckov } from "./checkov.js";

/**
 * Run all available external tools and return combined findings.
 * Falls back gracefully when tools aren't installed.
 */
export async function runAllTools(projectPath: string): Promise<{
  findings: Vulnerability[];
  toolsRun: string[];
  toolsSkipped: string[];
}> {
  const findings: Vulnerability[] = [];
  const toolsRun: string[] = [];
  const toolsSkipped: string[] = [];

  // Semgrep (SAST)
  if (checkTool("semgrep").installed) {
    findings.push(...runSemgrep(projectPath));
    toolsRun.push("semgrep");
  } else {
    toolsSkipped.push("semgrep");
  }

  // Gitleaks (secrets)
  if (checkTool("gitleaks").installed) {
    findings.push(...runGitleaks(projectPath));
    toolsRun.push("gitleaks");
  } else {
    toolsSkipped.push("gitleaks");
  }

  // Trivy (SCA + IaC + secrets)
  if (checkTool("trivy").installed) {
    findings.push(...runTrivyFs(projectPath));
    toolsRun.push("trivy");
  } else {
    toolsSkipped.push("trivy");
  }

  // Checkov (IaC)
  if (checkTool("checkov").installed) {
    findings.push(...runCheckov(projectPath));
    toolsRun.push("checkov");
  } else {
    toolsSkipped.push("checkov");
  }

  return { findings, toolsRun, toolsSkipped };
}
