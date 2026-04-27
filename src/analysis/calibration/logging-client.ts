import type Anthropic from "@anthropic-ai/sdk";
import type { LLMClient } from "../../llm/index.js";

/**
 * Per-turn diagnostic logging for the variants calibration harness
 * (sub-PR A3b — see docs/path-forward.md Track A).
 *
 * Why this exists: when the agent loop returns 0 variants, the
 * calibration result alone can't tell us whether
 *   (a) the agent never reached for `find_ast_pattern` (model didn't
 *       use the seeded AST shape — design unproven, not disproven), or
 *   (b) the agent used the AST tool but its candidates didn't map
 *       back to the calibration target (design tested and missed).
 *
 * Without per-turn diagnostics, we can't distinguish (a) from (b),
 * which means we can't honestly evaluate the kill criterion. This
 * module wraps an `LLMClient` with a logger that records, per turn:
 * stop reason, tool calls (name + input), text preview, token usage.
 *
 * Privacy / safety:
 *  - The wrapper sits at the `LLMClient` boundary, NOT at the
 *    Anthropic / OpenAI client boundary. The API key is set on the
 *    underlying client and never appears in the parameters to
 *    `messages.create`, so it cannot leak into a turn record.
 *  - Tool inputs and text bodies are size-capped (see constants below)
 *    so a long file read doesn't bloat the log to multi-MB. Truncation
 *    is marked explicitly with `__truncated` so a reviewer can tell
 *    the boundary apart from a model that actually emitted that text.
 */

export interface TurnRecord {
  /** 1-based turn index inside the wrapped client's lifetime. */
  turn: number;
  /** ISO 8601 timestamp at the start of the turn. */
  timestamp: string;
  /** Wall-clock duration of the underlying `messages.create` call. */
  durationMs: number;
  /** Anthropic stop reason; `null` if the call threw before returning. */
  stopReason: string | null;
  /**
   * Tool calls emitted by the model on this turn. Empty array when
   * the response was pure text. The crucial signal for the kill-
   * criterion read is whether `find_ast_pattern` appears here.
   */
  toolCalls: Array<{ name: string; input: unknown }>;
  /** First text block, capped at TEXT_PREVIEW_CAP characters. */
  textPreview: string | null;
  /** Token usage from `response.usage`. */
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheReadInputTokens?: number;
  };
  /** Set when the underlying call threw; the error is re-thrown after logging. */
  error?: string;
}

const TEXT_PREVIEW_CAP = 400;
const TOOL_INPUT_PREVIEW_CAP = 1024;

function truncate(s: string, cap: number): string {
  return s.length <= cap ? s : `${s.slice(0, cap)}…[+${s.length - cap}]`;
}

/**
 * Best-effort serialization of a tool input for logging. Tool inputs
 * are typed as `unknown` (Anthropic's API surface), in practice always
 * an object — but a `find_ast_pattern` call with a long source predicate
 * could push past TOOL_INPUT_PREVIEW_CAP and bloat the log. When that
 * happens, return a marked-truncated stand-in so the consumer can tell
 * "model emitted exactly this" from "we truncated this on the way out".
 */
function previewToolInput(input: unknown): unknown {
  let json: string;
  try {
    json = JSON.stringify(input);
  } catch {
    return { __error: "unserializable input" };
  }
  if (json.length <= TOOL_INPUT_PREVIEW_CAP) return input;
  return {
    __truncated: true,
    preview: json.slice(0, TOOL_INPUT_PREVIEW_CAP),
    fullLength: json.length,
  };
}

/**
 * Wrap an `LLMClient` with a per-turn logger. The returned client is
 * structurally identical to the input — same `messages.create`
 * signature, same return shape — and forwards every call. The only
 * side effect is `onTurn(record)` after each call (success or
 * failure).
 *
 * Errors are logged AND re-thrown so the wrapped agent loop sees the
 * same failure mode it would have seen unwrapped (the variant-analyzer
 * catches at the case level).
 */
export function wrapLLMClientWithLogging(
  client: LLMClient,
  onTurn: (record: TurnRecord) => void
): LLMClient {
  let turnCount = 0;
  return {
    messages: {
      create: async (params: Anthropic.MessageCreateParams): Promise<Anthropic.Message> => {
        turnCount += 1;
        const turn = turnCount;
        const start = Date.now();
        const timestamp = new Date().toISOString();
        try {
          const response = await client.messages.create(params);
          const text = response.content.find((b) => b.type === "text");
          const toolUses = response.content.filter(
            (b): b is Anthropic.ToolUseBlock => b.type === "tool_use"
          );
          onTurn({
            turn,
            timestamp,
            durationMs: Date.now() - start,
            stopReason: response.stop_reason ?? null,
            toolCalls: toolUses.map((t) => ({
              name: t.name,
              input: previewToolInput(t.input),
            })),
            textPreview:
              text && text.type === "text" ? truncate(text.text, TEXT_PREVIEW_CAP) : null,
            usage: {
              inputTokens: response.usage.input_tokens,
              outputTokens: response.usage.output_tokens,
              cacheReadInputTokens: response.usage.cache_read_input_tokens ?? undefined,
            },
          });
          return response;
        } catch (err) {
          onTurn({
            turn,
            timestamp,
            durationMs: Date.now() - start,
            stopReason: null,
            toolCalls: [],
            textPreview: null,
            usage: { inputTokens: 0, outputTokens: 0 },
            error: err instanceof Error ? err.message : String(err),
          });
          throw err;
        }
      },
    },
  };
}
