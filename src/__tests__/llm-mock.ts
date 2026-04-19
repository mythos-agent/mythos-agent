import type Anthropic from "@anthropic-ai/sdk";

/**
 * Minimal shape of an Anthropic.Message that the agentic-loop code in
 * analyzer.ts / recon-agent.ts / hypothesis-agent.ts / exploit-agent.ts
 * / smart-fuzzer.ts / poc-generator.ts reads. The real type carries
 * more fields (usage, id, role, model, ...), but the loops only read
 * `stop_reason` and `content`, so the mock can stay small and be cast
 * at the boundary.
 */
export interface MockMessage {
  stop_reason: "tool_use" | "end_turn" | "max_tokens" | "stop_sequence";
  content: Array<
    | { type: "text"; text: string }
    | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  >;
}

/**
 * Minimal shape of the options any of the DI-accepting classes pass
 * to `client.messages.create()`. Tests assert on these to verify the
 * loop sent the expected system prompt, temperature, message sequence,
 * etc.
 */
export interface CreateCall {
  model: string;
  max_tokens: number;
  temperature?: number;
  system?: string | unknown[];
  tools?: unknown[];
  messages: unknown[];
}

/**
 * Build a scriptable stand-in for an Anthropic client. Each call to
 * `.messages.create()` pops the next scripted response; if the queue
 * is empty the mock throws with a clear diagnostic so tests that
 * under-script fail loudly rather than hang.
 *
 * Returns both the mock client and a live call log so tests can
 * assert on what the caller sent upstream (e.g., temperature=0
 * pinning per e6d1231, tool_result round-trips on tool-use turns,
 * correct system prompt selection).
 *
 * Works for any class that accepts an `Anthropic` via constructor DI:
 * AIAnalyzer (validated in analyzer-loop.test.ts) and, once they gain
 * the optional `client?` parameter, ReconAgent / HypothesisAgent /
 * ExploitAgent / SmartFuzzer / PocGenerator / ChainAnalyzer.
 */
export function createMockClient(responses: MockMessage[]): {
  client: Anthropic;
  calls: CreateCall[];
} {
  const calls: CreateCall[] = [];
  const queue = [...responses];

  const client = {
    messages: {
      create: async (opts: CreateCall): Promise<MockMessage> => {
        calls.push(opts);
        const next = queue.shift();
        if (!next) {
          throw new Error(
            `MockAnthropicClient: ran out of scripted responses on call #${calls.length}. ` +
              "Either the test is under-scripted, or the loop is making more calls than expected."
          );
        }
        return next;
      },
    },
  } as unknown as Anthropic;

  return { client, calls };
}
