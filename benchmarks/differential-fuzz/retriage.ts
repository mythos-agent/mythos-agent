/**
 * Re-triage an existing differential-fuzz report.json in place (well,
 * writing to report-triaged.json alongside it). Skips the parsing/fuzz
 * phase entirely — only the LLM categorization step runs.
 *
 * Usage:
 *   NODE_USE_ENV_PROXY=1 ANTHROPIC_API_KEY=sk-ant-... \
 *     node dist-benchmarks/benchmarks/differential-fuzz/retriage.js \
 *     benchmarks/differential-fuzz/results/<subdir>/report.json
 */
import fs from "node:fs";
import path from "node:path";
import { createLLMClient } from "../../src/llm/index.js";
import { DEFAULT_CONFIG } from "../../src/types/index.js";
import { triage } from "../../src/dast/differential-fuzzer/triage.js";
import type { FuzzReport } from "../../src/dast/differential-fuzzer/types.js";

async function main(): Promise<void> {
  const reportPath = process.argv[2];
  if (!reportPath) {
    console.error("usage: retriage <path/to/report.json>");
    process.exit(2);
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error("set ANTHROPIC_API_KEY");
    process.exit(2);
  }

  const report: FuzzReport = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
  console.log(`loaded ${report.classes.length} classes from ${reportPath}`);

  const config = { ...DEFAULT_CONFIG, apiKey: process.env.ANTHROPIC_API_KEY };
  const client = createLLMClient(config);

  const triaged = await triage(report.classes, client, config.model);

  const outPath = path.join(path.dirname(reportPath), "report-triaged.json");
  const out: FuzzReport = { ...report, classes: triaged };
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));

  const byCat: Record<string, number> = {};
  for (const c of triaged) byCat[c.category ?? "untriaged"] = (byCat[c.category ?? "untriaged"] ?? 0) + 1;
  console.log("triaged report ->", outPath);
  console.log("by category:", byCat);
}

void main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
