import { Worker } from "node:worker_threads";
import type { ParserId, ParserResult } from "./types.js";

/** The minimal worker surface the pool depends on — lets tests inject fakes. */
export interface WorkerLike {
  postMessage(value: unknown): void;
  once(event: "message", cb: (value: ParserResult) => void): void;
  once(event: "error", cb: (err: unknown) => void): void;
  removeAllListeners(): void;
  terminate(): void;
}

// Resolved relative to THIS module so it works in both the dist/ and
// dist-benchmarks/ compiled layouts (the worker .js is always a sibling).
const WORKER_PATH = new URL("./worker.js", import.meta.url);

function spawnRealWorker(): WorkerLike {
  return new Worker(WORKER_PATH) as unknown as WorkerLike;
}

export interface WorkerPoolOptions {
  /**
   * Initial number of workers. Does NOT cap concurrency — if more
   * `runParse` calls are in flight than there are pooled workers, extra
   * workers are spawned on demand and returned to the pool on completion.
   * Default 4.
   */
  size?: number;
  timeoutMs?: number;
  /** Override worker creation — used by tests to inject fakes. */
  spawn?: () => WorkerLike;
}

/**
 * A small pool of persistent workers. Each `runParse` call races the
 * worker's response against a per-call timeout; on timeout the worker is
 * terminated (it hung) and replaced, and the call resolves `{ hang: true }`.
 */
export class WorkerPool {
  private readonly spawn: () => WorkerLike;
  private readonly timeoutMs: number;
  private readonly available: WorkerLike[];

  constructor(opts: WorkerPoolOptions = {}) {
    this.spawn = opts.spawn ?? spawnRealWorker;
    this.timeoutMs = opts.timeoutMs ?? 1000;
    this.available = Array.from({ length: opts.size ?? 4 }, () => this.spawn());
  }

  runParse(parserId: ParserId | "__hang__", input: string): Promise<ParserResult> {
    const worker = this.available.pop() ?? this.spawn();
    return new Promise<ParserResult>((resolve) => {
      const finish = (result: ParserResult, dead: boolean) => {
        clearTimeout(timer);
        worker.removeAllListeners();
        if (dead) {
          // Hung/crashed worker is terminated and dropped from the pool;
          // the next runParse spawns a fresh one on demand (lazy replacement).
          worker.terminate();
        } else {
          this.available.push(worker);
        }
        resolve(result);
      };
      const timer = setTimeout(() => finish({ hang: true }, true), this.timeoutMs);
      worker.once("message", (result) => finish(result, false));
      worker.once("error", (err) => finish({ error: String(err) }, true));
      worker.postMessage({ parserId, input });
    });
  }

  /**
   * Terminate all pooled workers. Precondition: call only after every
   * in-flight `runParse` promise has settled — a worker that is mid-parse
   * is not in the pool and would not be terminated here.
   */
  async destroy(): Promise<void> {
    for (const w of this.available) w.terminate();
    this.available.length = 0;
  }
}
