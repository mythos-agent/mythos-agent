/**
 * Variants v2 calibration runner — sub-PR A3b of issue #48 / Track A.
 *
 * For each CVE Replay case with a `calibration_target`, this script:
 *   1. Live-clones the upstream repo to `fixtures/<ghsa>/` (or reuses
 *      an existing clone) and checks out the case's vulnerable_commit.
 *   2. Builds an enriched CveInfo from A1's seed pattern (the
 *      structured `RootCausePattern` becomes the `rootCause` field
 *      in the variant-analyzer prompt — see
 *      src/analysis/calibration/agent-runner.ts).
 *   3. Runs `VariantAnalyzer.searchForVariants` against the
 *      vulnerable checkout. The `find_ast_pattern` tool from A2 is
 *      automatically available to the agent loop.
 *   4. Computes calibration_target overlap on the returned variants
 *      and writes a per-case JSON result.
 *
 * Cost: each case is one variant-analyzer agent loop, capped at
 * MAX_TURNS=20 in the analyzer. Empirically that's $0.50–$2 per case
 * with Claude Sonnet 4.6. See `docs/research/2026-04-26-variant-hunt-
 * experiment.md` for similar order-of-magnitude numbers.
 *
 * The script is the CLI shell; the per-case logic lives in
 * `src/analysis/calibration/agent-runner.ts` so it's testable with a
 * mock client (see runner.test.ts).
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration
 *   ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:variants-calibration -- --case GHSA-c2qf-rxjj-qqgw
 *   OPENAI_API_KEY=sk-... npm run benchmark:variants-calibration -- --provider openai --model qwen-...
 *
 * Exit codes:
 *   0 — all cases ran (matched or not, both report truthfully)
 *   1 — at least one case errored before producing a result
 *   2 — harness internal error (no cases match filter, missing env, etc.)
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { runAgentCalibration } from "../../src/analysis/calibration/agent-runner.js";
import type { CalibrationCaseFile } from "../../src/analysis/calibration/types.js";
import { DEFAULT_CONFIG, type MythosConfig } from "../../src/types/index.js";

const __filename = fileURLToPath(import.meta.url);

function findRepoRoot(start: string): string {
  let dir = start;
  while (dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    dir = path.dirname(dir);
  }
  throw new Error(`Could not locate repo root from ${start}`);
}
const REPO_ROOT = findRepoRoot(path.dirname(__filename));
const HARNESS_DIR = path.join(REPO_ROOT, "benchmarks", "variants-calibration");
const CASES_DIR = path.join(REPO_ROOT, "benchmarks", "cve-replay", "cases");
const FIXTURES_DIR = path.join(HARNESS_DIR, "fixtures");
const RESULTS_DIR = path.join(HARNESS_DIR, "results");

interface CliOptions {
  caseFilter?: string;
  provider: string;
  model?: string;
  resultsSubdir?: string;
  json: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { provider: "anthropic", json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--case") opts.caseFilter = argv[++i];
    else if (a === "--provider") opts.provider = argv[++i];
    else if (a === "--model") opts.model = argv[++i];
    else if (a === "--results-subdir") opts.resultsSubdir = argv[++i];
    else if (a === "--json") opts.json = true;
    else if (a === "--help" || a === "-h") {
      console.log(
        `Usage: variants-calibration [--case GHSA-xxxx] [--provider anthropic|openai|...] [--model NAME] [--results-subdir DIR] [--json]`
      );
      process.exit(0);
    }
  }
  return opts;
}

function loadCalibrationCases(filter?: string): CalibrationCaseFile[] {
  if (!fs.existsSync(CASES_DIR)) {
    throw new Error(`Cases directory not found: ${CASES_DIR}`);
  }
  const files = fs
    .readdirSync(CASES_DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"));
  const cases: (CalibrationCaseFile & { repo: string; vulnerable_commit: string })[] = [];
  for (const f of files) {
    const raw = fs.readFileSync(path.join(CASES_DIR, f), "utf-8");
    const parsed = JSON.parse(raw) as CalibrationCaseFile & {
      repo: string;
      vulnerable_commit: string;
    };
    // Only cases with a calibration_target participate. Observational
    // cases without one are correctly skipped here (not surfaced as
    // failures).
    if (!parsed.calibration_target) continue;
    if (filter && parsed.ghsa_id !== filter) continue;
    cases.push(parsed);
  }
  if (filter && cases.length === 0) {
    throw new Error(`No calibration case matched --case ${filter}`);
  }
  return cases;
}

function ensureFixture(repoUrl: string, ghsaId: string, log: (s: string) => void): string {
  const dest = path.join(FIXTURES_DIR, ghsaId);
  fs.mkdirSync(FIXTURES_DIR, { recursive: true });
  if (!fs.existsSync(path.join(dest, ".git"))) {
    log(`  cloning ${repoUrl} → ${path.relative(HARNESS_DIR, dest)}`);
    execFileSync("git", ["clone", "--filter=blob:none", "--no-checkout", repoUrl, dest], {
      stdio: ["ignore", "ignore", "inherit"],
    });
  }
  return dest;
}

function checkout(repoPath: string, sha: string): void {
  try {
    execFileSync("git", ["cat-file", "-e", sha], { cwd: repoPath, stdio: "ignore" });
  } catch {
    execFileSync("git", ["fetch", "--depth", "1", "origin", sha], {
      cwd: repoPath,
      stdio: ["ignore", "ignore", "inherit"],
    });
  }
  execFileSync("git", ["checkout", "--force", sha], {
    cwd: repoPath,
    stdio: ["ignore", "ignore", "inherit"],
  });
  execFileSync("git", ["clean", "-fdx"], { cwd: repoPath, stdio: "ignore" });
}

function buildConfig(opts: CliOptions): MythosConfig {
  const config: MythosConfig = { ...DEFAULT_CONFIG, provider: opts.provider };
  if (opts.model) config.model = opts.model;
  // The factory in src/llm/index.ts picks the correct env var based
  // on provider; we just set whichever API key the user supplied so
  // the analyzer's createLLMClient call gets a usable credential.
  config.apiKey = process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY;
  return config;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const log = (s: string): void => {
    if (!opts.json) console.error(s);
  };

  if (!process.env.ANTHROPIC_API_KEY && !process.env.OPENAI_API_KEY) {
    console.error(
      "Error: set ANTHROPIC_API_KEY or OPENAI_API_KEY before running this harness."
    );
    process.exit(2);
  }

  const cases = loadCalibrationCases(opts.caseFilter);
  log(`variants-calibration: running ${cases.length} case(s)`);

  const subdir =
    opts.resultsSubdir ?? new Date().toISOString().replace(/[:.]/g, "-");
  const resultsPath = path.join(RESULTS_DIR, subdir);
  fs.mkdirSync(resultsPath, { recursive: true });
  log(`results → ${path.relative(REPO_ROOT, resultsPath)}`);

  const config = buildConfig(opts);
  const summary: Array<{ ghsa: string; cve: string; matched: boolean; durationMs: number; error?: string }> = [];
  let errored = 0;

  for (const c of cases as Array<CalibrationCaseFile & { repo: string }>) {
    log(`\n[${c.ghsa_id}] ${c.cve_id ?? ""}`);
    let repoPath: string;
    try {
      repoPath = ensureFixture(c.repo, c.ghsa_id, log);
      checkout(repoPath, c.vulnerable_commit);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`  CLONE/CHECKOUT FAILED: ${msg}`);
      summary.push({
        ghsa: c.ghsa_id,
        cve: c.cve_id ?? "-",
        matched: false,
        durationMs: 0,
        error: msg,
      });
      errored++;
      continue;
    }

    const result = await runAgentCalibration(c, { projectPath: repoPath, config });

    const outPath = path.join(resultsPath, `${c.ghsa_id}.json`);
    fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
    log(
      `  ${result.matched ? "MATCH" : "miss"} — variants=${result.variantsFound}, overlapping=${result.overlappingVariants}, ${result.durationMs}ms`
    );
    if (result.error) {
      log(`  error: ${result.error}`);
      errored++;
    }
    summary.push({
      ghsa: c.ghsa_id,
      cve: c.cve_id ?? "-",
      matched: result.matched,
      durationMs: result.durationMs,
      error: result.error,
    });
  }

  const summaryPath = path.join(resultsPath, "summary.json");
  fs.writeFileSync(summaryPath, JSON.stringify({ runAt: new Date().toISOString(), config: { provider: config.provider, model: config.model }, results: summary }, null, 2));

  if (opts.json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  } else {
    log("\nvariants-calibration scoreboard");
    log("=".repeat(72));
    let matched = 0;
    for (const r of summary) {
      if (r.matched) matched++;
      log(
        `  ${r.ghsa.padEnd(22)} ${r.cve.padEnd(20)} ${(r.matched ? "MATCH" : "miss").padEnd(6)} ${r.durationMs}ms` +
          (r.error ? ` (error)` : "")
      );
    }
    log("-".repeat(72));
    log(`matched: ${matched} / ${summary.length}    errored: ${errored}    (target: ≥1 — kill criterion 2026-10-26)`);
  }

  process.exit(errored > 0 ? 1 : 0);
}

void main().catch((err: unknown) => {
  console.error(`harness internal error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});
