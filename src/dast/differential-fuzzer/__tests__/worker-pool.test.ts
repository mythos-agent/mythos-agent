import { describe, it, expect } from "vitest";
import { WorkerPool, type WorkerLike } from "../worker-pool.js";
import type { ParserResult } from "../types.js";

/** A fake worker that simulates one of three behaviors. */
function fakeWorker(behavior: "ok" | "hang" | "error"): WorkerLike {
  let onMessage: ((v: ParserResult) => void) | undefined;
  let onError: ((e: unknown) => void) | undefined;
  return {
    postMessage() {
      if (behavior === "ok") setTimeout(() => onMessage?.({ hostname: "ok.com" }), 0);
      else if (behavior === "error") setTimeout(() => onError?.(new Error("boom")), 0);
      // "hang": never responds
    },
    once(event: "message" | "error", cb: (v: never) => void) {
      if (event === "message") onMessage = cb as (v: ParserResult) => void;
      else onError = cb as (e: unknown) => void;
    },
    removeAllListeners() {
      onMessage = undefined;
      onError = undefined;
    },
    terminate() {},
  };
}

describe("WorkerPool", () => {
  it("resolves with the parser result on a normal response", async () => {
    const pool = new WorkerPool({ size: 1, spawn: () => fakeWorker("ok") });
    const r = await pool.runParse("native-url", "http://x");
    expect(r).toEqual({ hostname: "ok.com" });
    await pool.destroy();
  });

  it("resolves with { hang: true } when a parse exceeds the timeout", async () => {
    const pool = new WorkerPool({ size: 1, timeoutMs: 20, spawn: () => fakeWorker("hang") });
    const r = await pool.runParse("native-url", "http://x");
    expect(r).toEqual({ hang: true });
    await pool.destroy();
  });

  it("resolves with an error result when the worker errors", async () => {
    const pool = new WorkerPool({ size: 1, spawn: () => fakeWorker("error") });
    const r = await pool.runParse("native-url", "http://x");
    expect(r.error).toContain("boom");
    await pool.destroy();
  });

  it("keeps serving calls after a hang (worker was replaced)", async () => {
    let behavior: "hang" | "ok" = "hang";
    const pool = new WorkerPool({
      size: 1,
      timeoutMs: 20,
      spawn: () => fakeWorker(behavior),
    });
    expect(await pool.runParse("native-url", "a")).toEqual({ hang: true });
    behavior = "ok"; // the replacement worker behaves normally
    expect(await pool.runParse("native-url", "b")).toEqual({ hostname: "ok.com" });
    await pool.destroy();
  });
});
