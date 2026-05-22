/**
 * Differential URL-parser fuzzer benchmark runner.
 *
 * Runs `runDifferentialFuzz` against all three built-in parsers
 * (native-url, url-parse, legacy-url), prints a scoreboard, and writes
 * a JSON report to `benchmarks/differential-fuzz/results/<subdir>/report.json`.
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:differential-fuzz
 *   ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:differential-fuzz -- --count 500 --seed 42
 *   OPENAI_API_KEY=sk-... npm run benchmark:differential-fuzz -- --provider openai --model qwen-plus \
 *     --base-url https://dashscope.aliyuncs.com/compatible-mode/v1
 *
 * Exit codes:
 *   0 — run completed (report written)
 *   1 — missing credentials or runtime error
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createLLMClient } from "../../src/llm/index.js";
import { DEFAULT_CONFIG, type MythosConfig } from "../../src/types/index.js";
import { runDifferentialFuzz } from "../../src/dast/differential-fuzzer/index.js";

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

interface CliOptions {
  count: number;
  seed: number;
  resultsSubdir?: string;
  provider: string;
  model?: string;
  baseUrl?: string;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { count: 2000, seed: 1, provider: "anthropic" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--count") opts.count = Number(argv[++i]);
    else if (a === "--seed") opts.seed = Number(argv[++i]);
    else if (a === "--results-subdir") opts.resultsSubdir = argv[++i];
    else if (a === "--provider") opts.provider = argv[++i];
    else if (a === "--model") opts.model = argv[++i];
    else if (a === "--base-url") opts.baseUrl = argv[++i];
    else if (a === "--help" || a === "-h") {
      console.log(
        `Usage: differential-fuzz [--count N] [--seed N] [--results-subdir DIR]\n` +
          `                        [--provider anthropic|openai|...] [--model NAME] [--base-url URL]\n\n` +
          `Defaults: count=2000, seed=1, provider=anthropic\n\n` +
          `Env-var fallbacks for credentials:\n` +
          `  ANTHROPIC_API_KEY  (default provider)\n` +
          `  OPENAI_API_KEY     (provider: openai / openrouter / vllm / lmstudio)\n` +
          `  DASHSCOPE_API_KEY  (Qwen via Alibaba DashScope OpenAI-compat endpoint)\n` +
          `  MYTHOS_BASE_URL    (overrides --base-url; useful when shelling out)\n\n` +
          `Examples:\n` +
          `  ANTHROPIC_API_KEY=sk-ant-... npm run benchmark:differential-fuzz\n` +
          `  DASHSCOPE_API_KEY=sk-... npm run benchmark:differential-fuzz -- \\\n` +
          `    --provider openai --model qwen-plus \\\n` +
          `    --base-url https://dashscope.aliyuncs.com/compatible-mode/v1`
      );
      process.exit(0);
    }
  }
  return opts;
}

function buildConfig(opts: CliOptions): MythosConfig {
  const config: MythosConfig = { ...DEFAULT_CONFIG, provider: opts.provider };
  if (opts.model) config.model = opts.model;

  // API key resolution — mirrors variants-calibration/run.ts.
  config.apiKey =
    opts.provider === "anthropic"
      ? process.env.ANTHROPIC_API_KEY
      : process.env.OPENAI_API_KEY ||
        process.env.DASHSCOPE_API_KEY ||
        process.env.ANTHROPIC_API_KEY;

  // Base URL resolution: explicit --base-url wins, else MYTHOS_BASE_URL env,
  // else OPENAI_BASE_URL (python/openai-sdk compatible), else undefined.
  config.baseURL =
    opts.baseUrl || process.env.MYTHOS_BASE_URL || process.env.OPENAI_BASE_URL;

  return config;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));

  if (
    !process.env.ANTHROPIC_API_KEY &&
    !process.env.OPENAI_API_KEY &&
    !process.env.DASHSCOPE_API_KEY
  ) {
    console.error(
      "Error: set ANTHROPIC_API_KEY, OPENAI_API_KEY, or DASHSCOPE_API_KEY before running this benchmark. See --help for examples."
    );
    process.exit(1);
  }

  const config = buildConfig(opts);
  const client = createLLMClient(config);

  const subdir =
    opts.resultsSubdir ?? new Date().toISOString().replace(/[:.]/g, "-");

  console.log(`differential-fuzz: count=${opts.count} seed=${opts.seed}`);

  const report = await runDifferentialFuzz({
    count: opts.count,
    seed: opts.seed,
    model: config.model,
    client,
  });

  const outDir = path.join(REPO_ROOT, "benchmarks", "differential-fuzz", "results", subdir);
  fs.mkdirSync(outDir, { recursive: true });
  const reportPath = path.join(outDir, "report.json");
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

  const exploit = report.classes.filter((c) => c.category === "likely-exploitable").length;
  const dos = report.classes.filter((c) => c.category === "dos").length;

  console.log("\ndifferential-fuzz scoreboard");
  console.log("=".repeat(60));
  console.log(`  inputs tested:        ${report.inputsTested}`);
  console.log(`  divergence classes:   ${report.classes.length}`);
  console.log(`  likely-exploitable:   ${exploit}`);
  console.log(`  dos:                  ${dos}`);
  console.log("-".repeat(60));
  console.log(`  report -> ${path.relative(REPO_ROOT, reportPath)}`);
  for (const c of report.classes.slice(0, 10)) {
    console.log(
      `  [${c.category ?? "untriaged"}] ${c.kind}/${c.field ?? "-"} ` +
        `${c.parserA} vs ${c.parserB} x${c.count}`
    );
  }
}

void main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
