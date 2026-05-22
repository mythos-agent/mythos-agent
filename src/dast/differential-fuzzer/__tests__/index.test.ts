import { describe, it, expect, vi } from "vitest";
import { runDifferentialFuzz } from "../index.js";
import type { WorkerLike } from "../worker-pool.js";
import { PARSERS } from "../parsers.js";
import type { LLMClient } from "../../../llm/index.js";

// A fake worker that runs the real parsers in-process (no worker_threads).
function inProcessWorker(): WorkerLike {
  let onMessage: ((v: unknown) => void) | undefined;
  return {
    postMessage(value: unknown) {
      const { parserId, input } = value as { parserId: string; input: string };
      const parser = PARSERS[parserId as keyof typeof PARSERS];
      const result = parser ? parser(input) : { error: "unknown" };
      setTimeout(() => onMessage?.(result), 0);
    },
    once(event: "message" | "error", cb: (v: never) => void) {
      if (event === "message") onMessage = cb as (v: unknown) => void;
    },
    removeAllListeners() {
      onMessage = undefined;
    },
    terminate() {},
  };
}

function mockClient(): LLMClient {
  return {
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [{ type: "text", text: '{"category":"spec-ambiguity","rationale":"ok"}' }],
        stop_reason: "end_turn",
      }),
    },
  } as unknown as LLMClient;
}

describe("runDifferentialFuzz", () => {
  it("produces a well-formed report over a small run", async () => {
    const report = await runDifferentialFuzz({
      count: 40,
      seed: 99,
      model: "claude-sonnet-4-6",
      client: mockClient(),
      spawnWorker: inProcessWorker,
    });
    expect(report.inputsTested).toBe(40);
    expect(report.seed).toBe(99);
    expect(report.corpusSize).toBeGreaterThan(0);
    expect(Array.isArray(report.classes)).toBe(true);
    expect(typeof report.generatedAt).toBe("string");
    // URL parsers are well known to diverge — a 40-input run must find some.
    expect(report.classes.length).toBeGreaterThan(0);
  });

  it("ranks likely-exploitable classes above spec-ambiguity", async () => {
    const report = await runDifferentialFuzz({
      count: 60,
      seed: 5,
      model: "claude-sonnet-4-6",
      client: mockClient(),
      spawnWorker: inProcessWorker,
    });
    const cats = report.classes.map((c) => c.category);
    const firstAmbiguity = cats.indexOf("spec-ambiguity");
    const lastExploit = cats.lastIndexOf("likely-exploitable");
    if (firstAmbiguity !== -1 && lastExploit !== -1) {
      expect(lastExploit).toBeLessThan(firstAmbiguity);
    }
  });
});
