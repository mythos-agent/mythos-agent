import { describe, it, expect } from "vitest";
import http from "node:http";
import { createLLMClient, resolveModelForProvider } from "../index.js";
import { DEFAULT_CONFIG, type MythosConfig } from "../../types/index.js";

/**
 * Proves the model that reaches the wire for an OrcaRouter config is the
 * resolved OrcaRouter model (`orcarouter/auto` by default), not the
 * Anthropic-shaped `DEFAULT_CONFIG.model`, and that no other provider's
 * request shape changed.
 */

interface Seen {
  path?: string;
  model?: string;
  auth?: string;
}

async function capture(config: MythosConfig, body?: Record<string, unknown>): Promise<Seen[]> {
  const seen: Seen[] = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const parsed = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      seen.push({ path: req.url, model: parsed.model as string, auth: req.headers.authorization });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: "cmpl-1",
          model: parsed.model,
          choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 1, completion_tokens: 1 },
        })
      );
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  try {
    const client = createLLMClient({
      ...config,
      baseURL: `http://127.0.0.1:${port}/v1`,
    });
    await client.messages.create({
      model: resolveModelForProvider(config),
      max_tokens: 8,
      ...(body ?? {}),
      messages: [{ role: "user", content: "hi" }],
    });
  } finally {
    server.close();
  }
  return seen;
}

describe("model resolution reaches the provider request", () => {
  it("sends orcarouter/auto when the config still carries the anthropic default", async () => {
    const seen = await capture({
      ...structuredClone(DEFAULT_CONFIG),
      provider: "orcarouter",
      apiKey: "sk-orca-fake-aaaa",
    });
    expect(seen[0].path).toBe("/v1/chat/completions");
    expect(seen[0].model).toBe("orcarouter/auto");
  });

  it("sends the chosen cyber-tier model id verbatim", async () => {
    const seen = await capture({
      ...structuredClone(DEFAULT_CONFIG),
      provider: "orcarouter",
      apiKey: "sk-orca-fake-bbbb",
      model: "orcacyber-zero-1.5",
    });
    expect(seen[0].model).toBe("orcacyber-zero-1.5");
  });

  it("keeps OpenAI-compatible providers on their own request shape", async () => {
    const seen = await capture({
      ...structuredClone(DEFAULT_CONFIG),
      provider: "custom",
      apiKey: "sk-test",
      model: "qwen-plus",
    });
    expect(seen[0].path).toBe("/v1/chat/completions");
    expect(seen[0].model).toBe("qwen-plus");
  });
});
