import { describe, it, expect } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";

import {
  discoverOrcaRouterModels,
  parseModelCatalog,
  isChatCapableModel,
  seedModels,
  providerUsesOrcaRouterCatalog,
} from "../orcarouter-models.js";
import { ORCAROUTER_DEFAULT_MODEL, ORCAROUTER_FALLBACK_MODEL } from "../orcarouter.js";
import { createLLMClient } from "../index.js";
import { DEFAULT_CONFIG, type MythosConfig } from "../../types/index.js";

const REPO_ROOT = path.resolve(__dirname, "../../..");
const FAKE_KEY = "sk-orca-fake-000000000000000000000";

/** Build a fake `fetch` returning a fixed body/status. */
function fakeFetch(body: string, status = 200): typeof fetch {
  return (async () =>
    new Response(body, {
      status,
      headers: { "Content-Type": "application/json" },
    })) as typeof fetch;
}

const LIVE_CATALOG = {
  data: [
    { id: "openai/gpt-5.5", supported_endpoint_types: ["openai", "openai-response"] },
    {
      id: "vendor/vision-chat",
      supported_endpoint_types: ["openai"],
      architecture: { input_modalities: ["text", "image"], output_modalities: ["text"] },
    },
    { id: "vendor/embed", supported_endpoint_types: ["embeddings"] },
    { id: "vendor/image-gen", supported_endpoint_types: ["image-generation"] },
    { id: "vendor/jina-rerank-1", supported_endpoint_types: ["jina-rerank"] },
    { id: "vendor/video-1", supported_endpoint_types: ["openai-video"] },
    { id: ORCAROUTER_DEFAULT_MODEL, supported_endpoint_types: ["openai"] },
    { id: ORCAROUTER_FALLBACK_MODEL, supported_endpoint_types: ["openai"] },
  ],
};

describe("parseModelCatalog capability filtering", () => {
  it("keeps chat routes and drops embedding / image / video / rerank routes", () => {
    const ids = parseModelCatalog(LIVE_CATALOG).map((m) => m.id);
    expect(ids).toContain("openai/gpt-5.5");
    expect(ids).toContain("vendor/vision-chat"); // chat first; modalities are a separate axis
    expect(ids).toContain(ORCAROUTER_DEFAULT_MODEL);
    expect(ids).not.toContain("vendor/embed");
    expect(ids).not.toContain("vendor/image-gen");
    expect(ids).not.toContain("vendor/jina-rerank-1");
    expect(ids).not.toContain("vendor/video-1");
  });

  it("puts the default model and cyber tier ahead of the long tail", () => {
    const ids = parseModelCatalog({
      data: [
        { id: "zzz/last", supported_endpoint_types: ["openai"] },
        { id: ORCAROUTER_FALLBACK_MODEL, supported_endpoint_types: ["openai"] },
        { id: ORCAROUTER_DEFAULT_MODEL, supported_endpoint_types: ["openai"] },
        { id: "orcacyber-ultra-1.0", supported_endpoint_types: ["openai"] },
      ],
    }).map((m) => m.id);
    expect(ids[0]).toBe("orcacyber-ultra-1.0");
    expect(ids[1]).toBe(ORCAROUTER_DEFAULT_MODEL);
    expect(ids[2]).toBe(ORCAROUTER_FALLBACK_MODEL);
  });

  it("fails closed on rows with no recognisable capability metadata", () => {
    expect(isChatCapableModel({ id: "lowercase-no-namespace" })).toBe(false);
    expect(isChatCapableModel({ id: "vendor/chat-1" })).toBe(true);
    expect(isChatCapableModel({ id: "" })).toBe(false);
    expect(
      isChatCapableModel({ id: "vendor/mixed", supported_endpoint_types: ["openai", "embeddings"] })
    ).toBe(true);
  });

  it("bounds item count and de-duplicates ids", () => {
    const data = Array.from({ length: 20 }, (_, i) => ({
      id: `vendor/m${i % 10}`,
      supported_endpoint_types: ["openai"],
    }));
    expect(parseModelCatalog({ data }, 5)).toHaveLength(5);
    expect(new Set(parseModelCatalog({ data }).map((m) => m.id)).size).toBe(
      parseModelCatalog({ data }).length
    );
  });

  it("reads the context window when reported", () => {
    const [model] = parseModelCatalog({
      data: [{ id: "vendor/big", supported_endpoint_types: ["openai"], context_length: 200000 }],
    });
    expect(model.contextWindow).toBe(200000);
    expect(model.source).toBe("live");
  });
});

describe("discoverOrcaRouterModels", () => {
  it("returns the live catalog and marks it authoritative (no seed mixed in)", async () => {
    const result = await discoverOrcaRouterModels({
      apiKey: FAKE_KEY,
      fetchImpl: fakeFetch(JSON.stringify(LIVE_CATALOG)),
    });
    expect(result.degraded).toBe(false);
    expect(result.source).toBe("live");
    expect(result.status).toBe("ok");
    expect(result.models.every((m) => m.source === "live")).toBe(true);
    // seed-only rows that the live catalog did not return must not appear
    expect(result.models.map((m) => m.id)).not.toContain("anthropic/claude-opus-4.8");
  });

  it("sends the Bearer key to {base}/models with the chat capability filter", async () => {
    let seenUrl = "";
    let seenAuth = "";
    const spy = (async (input: string | URL | Request, init?: RequestInit) => {
      seenUrl = String(input);
      seenAuth = String((init?.headers as Record<string, string>).Authorization);
      return new Response(JSON.stringify(LIVE_CATALOG), { status: 200 });
    }) as typeof fetch;
    await discoverOrcaRouterModels({ apiKey: FAKE_KEY, fetchImpl: spy });
    expect(seenUrl).toBe("https://api.orcarouter.ai/v1/models?capability=chat");
    expect(seenAuth).toBe(`Bearer ${FAKE_KEY}`);
  });

  it("falls back to the verified seed on auth error without leaking the key", async () => {
    const result = await discoverOrcaRouterModels({
      apiKey: FAKE_KEY,
      fetchImpl: fakeFetch(`{"error":"invalid key ${FAKE_KEY}"}`, 401),
    });
    expect(result.degraded).toBe(true);
    expect(result.source).toBe("seed");
    expect(result.status).toBe("auth_error");
    expect(result.models.map((m) => m.id)).toEqual(seedModels().map((m) => m.id));
    expect(result.error ?? "").not.toContain(FAKE_KEY);
  });

  it("falls back to the verified seed on network failure and non-JSON bodies", async () => {
    const network = await discoverOrcaRouterModels({
      fetchImpl: (async () => {
        throw new Error("ECONNREFUSED");
      }) as typeof fetch,
    });
    expect(network.degraded).toBe(true);
    expect(network.status).toBe("network_error");

    const garbage = await discoverOrcaRouterModels({ fetchImpl: fakeFetch("<html>") });
    expect(garbage.degraded).toBe(true);
  });

  it("times out instead of hanging", async () => {
    const hanging = (async (_input: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      })) as typeof fetch;
    const result = await discoverOrcaRouterModels({ fetchImpl: hanging, timeoutMs: 20 });
    expect(result.degraded).toBe(true);
    expect(result.error).toMatch(/timeout/);
  });

  it("treats an empty catalog as degraded rather than free-form", async () => {
    const result = await discoverOrcaRouterModels({ fetchImpl: fakeFetch('{"data":[]}') });
    expect(result.degraded).toBe(true);
    expect(result.status).toBe("empty");
  });

  it("seed keeps cyber tier, default, fallback and known metadata ids", () => {
    const ids = seedModels().map((m) => m.id);
    expect(ids.slice(0, 2)).toEqual(["orcacyber-ultra-1.0", "orcacyber-zero-1.5"]);
    expect(ids).toContain(ORCAROUTER_DEFAULT_MODEL);
    expect(ids).toContain(ORCAROUTER_FALLBACK_MODEL);
    expect(providerUsesOrcaRouterCatalog("orcarouter")).toBe(true);
    expect(providerUsesOrcaRouterCatalog("openai")).toBe(false);
  });
});

/**
 * End-to-end through the provider code path: a config with
 * `provider: orcarouter` built by `createLLMClient` must hit
 * `{base}/chat/completions` on the OrcaRouter base URL with Bearer auth and
 * the vendor/model id unchanged, and errors must not echo the key.
 */
describe("OrcaRouter provider request path", () => {
  async function withServer<T>(
    handler: (req: http.IncomingMessage, body: string) => { status: number; payload: unknown },
    fn: (port: number, seen: Array<{ path?: string; auth?: string; model?: string }>) => Promise<T>
  ): Promise<T> {
    const seen: Array<{ path?: string; auth?: string; model?: string }> = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const parsed = body ? (JSON.parse(body) as { model?: string }) : {};
        seen.push({ path: req.url, auth: req.headers.authorization, model: parsed.model });
        const { status, payload } = handler(req, body);
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(payload));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    try {
      return await fn(port, seen);
    } finally {
      server.close();
    }
  }

  function orcaConfig(port: number, model: string): MythosConfig {
    return {
      ...structuredClone(DEFAULT_CONFIG),
      provider: "orcarouter",
      apiKey: FAKE_KEY,
      model,
      // Self-hosted loopback override exercises the same code path.
      baseURL: `http://127.0.0.1:${port}/v1`,
    };
  }

  it("uses the OpenAI chat-completions path and verbatim model id", async () => {
    await withServer(
      () => ({
        status: 200,
        payload: {
          id: "cmpl-1",
          model: "orcacyber-ultra-1.0",
          choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 1 },
        },
      }),
      async (port, seen) => {
        const client = createLLMClient(orcaConfig(port, "orcacyber-ultra-1.0"));
        const msg = await client.messages.create({
          model: "orcacyber-ultra-1.0",
          max_tokens: 16,
          messages: [{ role: "user", content: "hello" }],
        });
        expect(msg.content[0]).toMatchObject({ type: "text", text: "ok" });
        expect(seen).toHaveLength(1);
        expect(seen[0].path).toBe("/v1/chat/completions");
        expect(seen[0].auth).toContain(FAKE_KEY);
        expect(seen[0].model).toBe("orcacyber-ultra-1.0");
      }
    );
  });

  it("surfaces an upstream auth failure without leaking the key", async () => {
    await withServer(
      () => ({ status: 401, payload: { error: { message: `bad key ${FAKE_KEY}` } } }),
      async (port, seen) => {
        const client = createLLMClient(orcaConfig(port, "orcarouter/auto"));
        await expect(
          client.messages.create({
            model: "orcarouter/auto",
            max_tokens: 16,
            messages: [{ role: "user", content: "hello" }],
          })
        ).rejects.toSatisfy((err: unknown) => {
          const text = `${(err as Error).name} ${(err as Error).message}`;
          expect(text).toMatch(/401/);
          expect(text).not.toContain(FAKE_KEY);
          return true;
        });
        expect(seen[0].path).toBe("/v1/chat/completions");
      }
    );
  });
});

describe.runIf(!!process.env.ORCAROUTER_API_KEY)("live OrcaRouter (opt-in)", () => {
  it("discovers chat models from the real catalog", async () => {
    const result = await discoverOrcaRouterModels({
      apiKey: process.env.ORCAROUTER_API_KEY,
    });
    console.log(
      `[live] catalog status=${result.status} source=${result.source} count=${result.models.length}`
    );
    expect(result.status).toBe("ok");
    expect(result.models.length).toBeGreaterThan(0);
  });
});

function runAsync(cmd: string, args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd });
    let out = "";
    child.stdout.on("data", (c: Buffer) => (out += c.toString()));
    child.stderr.on("data", (c: Buffer) => (out += c.toString()));
    child.on("error", reject);
    child.on("close", () => resolve(out));
  });
}

/** Compile the CLI so a real subprocess can exercise `doctor` against a fake server. */
describe("CLI doctor reaches the OrcaRouter catalog endpoint", () => {
  it("builds the project and reports the model catalog as reachable", () => {
    const build = spawnSync(path.join(REPO_ROOT, "node_modules/.bin/tsc"), ["-p", REPO_ROOT], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
    });
    expect(build.status, build.stderr).toBe(0);

    const server = http.createServer((req, res) => {
      if (req.url === "/v1/models") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(LIVE_CATALOG));
        return;
      }
      res.writeHead(404).end();
    });
    return new Promise<void>((resolve, reject) => {
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as { port: number }).port;
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-orca-doctor-"));
        fs.writeFileSync(
          path.join(dir, ".mythos.yml"),
          `apiKey: "${FAKE_KEY}"\nprovider: orcarouter\nmodel: "${ORCAROUTER_DEFAULT_MODEL}"\nbaseURL: "http://127.0.0.1:${port}/v1"\n`
        );
        // Run the CLI from an async child process: a blocking spawnSync
        // would freeze this test's event loop, and the in-process fake
        // catalog server would never answer the request.
        runAsync(
          process.execPath,
          [path.join(REPO_ROOT, "dist/cli/index.js"), "doctor", "--path", dir],
          dir
        )
          .then((out) => {
            expect(out).toMatch(/API key accepted by the model catalog/);
            expect(out).toContain("orcarouter");
            expect(out).not.toContain(FAKE_KEY);
            resolve();
          })
          .catch(reject)
          .finally(() => {
            server.close();
            fs.rmSync(dir, { recursive: true, force: true });
          });
      });
    });
  }, 200000);
});
