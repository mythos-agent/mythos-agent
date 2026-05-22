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
          worker.terminate();
          // Spawn the replacement lazily (on next pop) so the spawn factory
          // is called after the caller has a chance to change its state.
          // We push a deferred sentinel by simply not returning the dead
          // worker — the pool will spawn fresh on next runParse if empty.
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

  async destroy(): Promise<void> {
    for (const w of this.available) w.terminate();
    this.available.length = 0;
  }
}
