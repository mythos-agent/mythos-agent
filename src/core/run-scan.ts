import { loadConfig } from "../config/config.js";
import type { MythosConfig } from "../types/index.js";
import { PatternScanner } from "../scanner/pattern-scanner.js";
import { SecretsScanner } from "../scanner/secrets-scanner.js";
import { DepScanner } from "../scanner/dep-scanner.js";
import { IacScanner } from "../scanner/iac-scanner.js";
import { LlmSecurityScanner } from "../scanner/llm-security-scanner.js";
import { ApiSecurityScanner } from "../scanner/api-security-scanner.js";
import { CloudSecurityScanner } from "../scanner/cloud-scanner.js";
import { HeadersScanner } from "../scanner/headers-scanner.js";
import { JwtScanner } from "../scanner/jwt-scanner.js";
import { SessionScanner } from "../scanner/session-scanner.js";
import { BusinessLogicScanner } from "../scanner/business-logic-scanner.js";
import { CryptoScanner } from "../scanner/crypto-scanner.js";
import { PrivacyScanner } from "../scanner/privacy-scanner.js";
import { RaceConditionScanner } from "../scanner/race-condition-scanner.js";
import { RedosScanner } from "../scanner/redos-scanner.js";
import { runAllTools } from "../tools/index.js";
import type { Vulnerability } from "../types/index.js";

// Phase-1 deterministic-scanner orchestration shared between CLI `scan` and
// HTTP API `POST /api/scan`. Before this helper existed, the two call sites
// drifted: scan.ts ran 15 scanners; api.ts ran 4 (review item #10). Adding
// a new scanner required two edits. Now the scanner list lives here, both
// callers opt in/out via flags, and "parity" is a code invariant rather
// than a review-cycle reminder.
//
// This helper intentionally does NOT handle Phase 2 (AI analysis) or Phase 3
// (vuln chaining). Those are CLI-side because they need interactive API-key
// handling and terminal UX; HTTP consumers who want AI results should hit
// /api/scan and then /api/results after the CLI has run. A future follow-up
// can promote AI/chain into runScan if an HTTP use case for them lands.

export interface RunScanOptions {
  // Opt-out flags. All default to true so callers that want "everything"
  // can pass `{}`. This matches the CLI's `--no-*` flag family semantic:
  // secrets run unless `--no-secrets`.
  secrets?: boolean;
  deps?: boolean;
  iac?: boolean;
  llm?: boolean;
  apiSec?: boolean;
  cloud?: boolean;
  headers?: boolean;
  jwt?: boolean;
  session?: boolean;
  bizLogic?: boolean;
  crypto?: boolean;
  privacy?: boolean;
  raceConditions?: boolean;
  redos?: boolean;

  // External tools (Semgrep, Gitleaks, Trivy, Checkov, Nuclei) default OFF
  // because their availability is environment-dependent — CLI's default
  // scan keeps them out. HTTP API opts in to match its historical behavior.
  includeExternalTools?: boolean;

  // Pre-resolved config. The CLI mutates config.scan.include/exclude in
  // `--diff` mode before running, so it passes the already-mutated object
  // to avoid a double loadConfig() that would lose the mutation. Other
  // callers (HTTP API, tests) leave this undefined and let runScan load.
  config?: MythosConfig;

  // Progress reporting for interactive callers (e.g. CLI spinners).
  // Non-interactive callers (HTTP API, tests) leave this undefined.
  onPhase?: (event: PhaseEvent) => void;
}

export interface PhaseEvent {
  id: PhaseId;
  label: string;
  state: "start" | "end" | "error";
  durationMs?: number;
  findings?: number;
  filesScanned?: number;
  error?: string;
}

export type PhaseId =
  | "pattern"
  | "secrets"
  | "deps"
  | "iac"
  | "llm"
  | "api-sec"
  | "cloud"
  | "headers"
  | "jwt"
  | "session"
  | "biz-logic"
  | "crypto"
  | "privacy"
  | "race-conditions"
  | "redos"
  | "external-tools";

export interface RunScanOutput {
  // Concatenation of all sub-arrays in the order PatternScanner →
  // other deterministic scanners → external tools. Callers that don't
  // need to distinguish provenance (HTTP API summary, most tests) use
  // this directly.
  findings: Vulnerability[];
  // Pattern-scanner findings, separated so the CLI's AIAnalyzer Phase 2
  // can verify them without also re-verifying already-deterministic
  // secrets/deps/iac/etc. results.
  patternFindings: Vulnerability[];
  // Non-pattern deterministic scanner findings (secrets, deps, iac,
  // llm, apiSec, cloud, headers, jwt, session, bizLogic, crypto,
  // privacy, raceConditions, redos) + external-tool findings when
  // includeExternalTools is on. These bypass AI verification in the
  // CLI Phase 2 flow — they're deterministic enough to trust as-is.
  deterministicFindings: Vulnerability[];
  filesScanned: number;
  languages: string[];
  toolsRun: string[];
  durationMs: number;
}

const ENABLED_BY_DEFAULT = true;
const on = (flag: boolean | undefined): boolean => (flag === undefined ? ENABLED_BY_DEFAULT : flag);

async function timed<T>(fn: () => Promise<T>): Promise<{ result: T; durationMs: number }> {
  const start = Date.now();
  const result = await fn();
  return { result, durationMs: Date.now() - start };
}

async function runPhase<T extends { findings: Vulnerability[]; filesScanned?: number }>(
  id: PhaseId,
  label: string,
  onPhase: RunScanOptions["onPhase"],
  work: () => Promise<T>
): Promise<Vulnerability[]> {
  onPhase?.({ id, label, state: "start" });
  try {
    const { result, durationMs } = await timed(work);
    onPhase?.({
      id,
      label,
      state: "end",
      durationMs,
      findings: result.findings.length,
      filesScanned: result.filesScanned,
    });
    return result.findings;
  } catch (err) {
    onPhase?.({
      id,
      label,
      state: "error",
      error: err instanceof Error ? err.message : String(err),
    });
    return [];
  }
}

export async function runScan(
  projectPath: string,
  opts: RunScanOptions = {}
): Promise<RunScanOutput> {
  const config = opts.config ?? loadConfig(projectPath);
  const start = Date.now();
  const patternFindings: Vulnerability[] = [];
  const deterministicFindings: Vulnerability[] = [];
  const toolsRun: string[] = [];

  // Phase 1 (pattern scanner) is always on — it's the baseline; it produces
  // the file-discovery metadata (filesScanned, languages) that the other
  // scanners don't, and disabling it would break the summary shape.
  opts.onPhase?.({ id: "pattern", label: "Pattern Scan", state: "start" });
  const patternStart = Date.now();
  let filesScanned = 0;
  let languages: string[] = [];
  try {
    const patternScanner = new PatternScanner(config);
    const patternResult = await patternScanner.scan(projectPath);
    patternFindings.push(...patternResult.findings);
    filesScanned = patternResult.filesScanned;
    languages = patternResult.languages;
    opts.onPhase?.({
      id: "pattern",
      label: "Pattern Scan",
      state: "end",
      durationMs: Date.now() - patternStart,
      findings: patternResult.findings.length,
      filesScanned,
    });
  } catch (err) {
    opts.onPhase?.({
      id: "pattern",
      label: "Pattern Scan",
      state: "error",
      error: err instanceof Error ? err.message : String(err),
    });
  }

  if (on(opts.secrets)) {
    deterministicFindings.push(
      ...(await runPhase("secrets", "Secrets Detection", opts.onPhase, () =>
        new SecretsScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.deps)) {
    deterministicFindings.push(
      ...(await runPhase("deps", "Dependency Scan (OSV)", opts.onPhase, () =>
        new DepScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.iac)) {
    deterministicFindings.push(
      ...(await runPhase("iac", "IaC Security Scan", opts.onPhase, () =>
        new IacScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.llm)) {
    deterministicFindings.push(
      ...(await runPhase("llm", "AI/LLM Security Scan", opts.onPhase, () =>
        new LlmSecurityScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.apiSec)) {
    deterministicFindings.push(
      ...(await runPhase("api-sec", "API Security Scan", opts.onPhase, () =>
        new ApiSecurityScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.cloud)) {
    deterministicFindings.push(
      ...(await runPhase("cloud", "Cloud Security Scan", opts.onPhase, () =>
        new CloudSecurityScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.headers)) {
    deterministicFindings.push(
      ...(await runPhase("headers", "Security Headers Scan", opts.onPhase, () =>
        new HeadersScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.jwt)) {
    deterministicFindings.push(
      ...(await runPhase("jwt", "JWT Security Scan", opts.onPhase, () =>
        new JwtScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.session)) {
    deterministicFindings.push(
      ...(await runPhase("session", "Session Security Scan", opts.onPhase, () =>
        new SessionScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.bizLogic)) {
    deterministicFindings.push(
      ...(await runPhase("biz-logic", "Business Logic Scan", opts.onPhase, () =>
        new BusinessLogicScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.crypto)) {
    deterministicFindings.push(
      ...(await runPhase("crypto", "Crypto Audit", opts.onPhase, () =>
        new CryptoScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.privacy)) {
    deterministicFindings.push(
      ...(await runPhase("privacy", "Privacy/GDPR Scan", opts.onPhase, () =>
        new PrivacyScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.raceConditions)) {
    deterministicFindings.push(
      ...(await runPhase("race-conditions", "Race Condition Scan", opts.onPhase, () =>
        new RaceConditionScanner().scan(projectPath)
      ))
    );
  }

  if (on(opts.redos)) {
    deterministicFindings.push(
      ...(await runPhase("redos", "ReDoS Scan", opts.onPhase, () =>
        new RedosScanner().scan(projectPath)
      ))
    );
  }

  if (opts.includeExternalTools === true) {
    opts.onPhase?.({ id: "external-tools", label: "External Tools", state: "start" });
    const extStart = Date.now();
    try {
      const { findings: external, toolsRun: ran } = await runAllTools(projectPath);
      deterministicFindings.push(...external);
      toolsRun.push(...ran);
      opts.onPhase?.({
        id: "external-tools",
        label: "External Tools",
        state: "end",
        durationMs: Date.now() - extStart,
        findings: external.length,
      });
    } catch (err) {
      opts.onPhase?.({
        id: "external-tools",
        label: "External Tools",
        state: "error",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return {
    findings: [...patternFindings, ...deterministicFindings],
    patternFindings,
    deterministicFindings,
    filesScanned,
    languages,
    toolsRun,
    durationMs: Date.now() - start,
  };
}
