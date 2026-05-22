import type { LLMClient } from "../../llm/index.js";
import { loadCorpus } from "./corpus.js";
import { mutate } from "./mutator.js";
import { WorkerPool, type WorkerLike } from "./worker-pool.js";
import { compare, classify } from "./engine.js";
import { triage } from "./triage.js";
import {
  FIELD_SEVERITY,
  type Divergence,
  type ParserId,
  type ParserResult,
  type TriagedDivergenceClass,
  type FuzzReport,
} from "./types.js";

export interface DifferentialFuzzOptions {
  /** Number of fuzzing inputs to generate. */
  count: number;
  /** RNG seed — fixes the input set for reproducibility. */
  seed: number;
  /** Model id for the triage LLM calls. */
  model: string;
  /** LLM client for triage. */
  client: LLMClient;
  /** Worker pool size. Default 4. */
  poolSize?: number;
  /** Per-parse timeout in ms. Default 1000. */
  timeoutMs?: number;
  /** Override worker creation — used by tests to avoid real worker_threads. */
  spawnWorker?: () => WorkerLike;
}

const CATEGORY_RANK: Record<string, number> = {
  "likely-exploitable": 3,
  dos: 2,
  "spec-ambiguity": 1,
};

/** Sort comparator: exploitable first, then by field severity, then by count. */
function rankClasses(a: TriagedDivergenceClass, b: TriagedDivergenceClass): number {
  const ca = CATEGORY_RANK[a.category ?? ""] ?? 0;
  const cb = CATEGORY_RANK[b.category ?? ""] ?? 0;
  if (ca !== cb) return cb - ca;
  const fa = a.field ? FIELD_SEVERITY[a.field] : 0;
  const fb = b.field ? FIELD_SEVERITY[b.field] : 0;
  if (fa !== fb) return fb - fa;
  return b.count - a.count;
}

/**
 * Run the differential URL-parser fuzzer end to end: load the corpus,
 * mutate it into `count` inputs, parse each through all three parsers in
 * worker-isolated calls, compare, dedup, LLM-triage, and rank.
 */
export async function runDifferentialFuzz(opts: DifferentialFuzzOptions): Promise<FuzzReport> {
  const corpus = loadCorpus();
  const inputs = mutate(corpus, opts.count, opts.seed);

  const pool = new WorkerPool({
    size: opts.poolSize,
    timeoutMs: opts.timeoutMs,
    spawn: opts.spawnWorker,
  });

  const divergences: Divergence[] = [];
  try {
    for (const input of inputs) {
      const ids: ParserId[] = ["native-url", "url-parse", "legacy-url"];
      const parsed = await Promise.all(ids.map((id) => pool.runParse(id, input)));
      const results: Record<ParserId, ParserResult> = {
        "native-url": parsed[0],
        "url-parse": parsed[1],
        "legacy-url": parsed[2],
      };
      divergences.push(...compare(input, results));
    }
  } finally {
    await pool.destroy();
  }

  const classes = classify(divergences);
  const triaged = await triage(classes, opts.client, opts.model);
  triaged.sort(rankClasses);

  return {
    generatedAt: new Date().toISOString(),
    seed: opts.seed,
    corpusSize: corpus.length,
    inputsTested: inputs.length,
    classes: triaged,
  };
}
