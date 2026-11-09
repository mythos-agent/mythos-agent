import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createProvider } from "../index.js";
import { OpenAICompatibleProvider } from "../openai-compatible.js";
import { INIT_PROVIDER_CHOICES } from "../../../cli/commands/init.js";
import { loadConfig, writeConfig } from "../../../config/config.js";
import { DEFAULT_CONFIG, type MythosConfig } from "../../../types/index.js";
import { ORCAROUTER_API_BASE_URL, ORCAROUTER_PROVIDER_LABEL } from "../../../llm/orcarouter.js";

const FAKE_KEY = "sk-orca-fake-registry-0000000000000000";

function cfg(overrides: Partial<MythosConfig> = {}): MythosConfig {
  return { ...structuredClone(DEFAULT_CONFIG), apiKey: FAKE_KEY, ...overrides };
}

function internals(p: OpenAICompatibleProvider): {
  baseUrl: string;
  model: string;
  apiKey: string;
} {
  return p as unknown as { baseUrl: string; model: string; apiKey: string };
}

describe("AIProvider registry", () => {
  it("registers OrcaRouter Cyber Inference as a named provider in init", () => {
    const orca = INIT_PROVIDER_CHOICES.find((c) => c.value === "orcarouter");
    expect(orca?.name).toContain(ORCAROUTER_PROVIDER_LABEL);
    expect(orca?.name).toContain("OrcaRouter");
    // Still selectable alongside every pre-existing choice.
    expect(INIT_PROVIDER_CHOICES.map((c) => c.value)).toEqual(
      expect.arrayContaining(["anthropic", "openai", "ollama", "lmstudio", "custom"])
    );
  });

  it("builds an OpenAI-compatible provider pinned to the OrcaRouter base URL", () => {
    const provider = createProvider(cfg({ provider: "orcarouter", model: "orcacyber-zero-1.5" }));
    expect(provider).toBeInstanceOf(OpenAICompatibleProvider);
    expect(provider.name).toBe(ORCAROUTER_PROVIDER_LABEL);
    const inner = internals(provider as OpenAICompatibleProvider);
    expect(inner.baseUrl).toBe(ORCAROUTER_API_BASE_URL);
    expect(inner.model).toBe("orcacyber-zero-1.5");
    expect(inner.apiKey).toBe(FAKE_KEY);
  });

  it("defaults the model to orcarouter/auto when the config is anthropic-shaped", () => {
    const provider = createProvider(cfg({ provider: "orcarouter" }));
    expect(internals(provider as OpenAICompatibleProvider).model).toBe("orcarouter/auto");
  });

  it("leaves the pre-existing providers' base URLs untouched", () => {
    const openai = createProvider(cfg({ provider: "openai" }));
    expect(internals(openai as OpenAICompatibleProvider).baseUrl).toBe("https://api.openai.com/v1");
    const ollama = createProvider(cfg({ provider: "ollama" }));
    expect(internals(ollama as OpenAICompatibleProvider).baseUrl).toBe("http://localhost:11434/v1");
  });
});

describe("credential handling for orcarouter", () => {
  const dirs: string[] = [];
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of ["MYTHOS_API_KEY", "SPHINX_API_KEY", "ANTHROPIC_API_KEY", "MYTHOS_MODEL"]) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    while (dirs.length) fs.rmSync(dirs.pop()!, { recursive: true, force: true });
  });

  it("reads the key from the project's existing config surface (.mythos.yml)", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-orca-cfg-"));
    dirs.push(dir);
    writeConfig(dir, { provider: "orcarouter", apiKey: FAKE_KEY, model: "orcarouter/fusion" });
    const config = loadConfig(dir);
    expect(config.provider).toBe("orcarouter");
    expect(config.apiKey).toBe(FAKE_KEY);
    expect(config.model).toBe("orcarouter/fusion");
  });

  it("lets MYTHOS_API_KEY update the key without touching other providers", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-orca-cfg-"));
    dirs.push(dir);
    writeConfig(dir, { provider: "orcarouter", apiKey: "sk-orca-old", model: "orcarouter/auto" });
    process.env.MYTHOS_API_KEY = "sk-orca-new";
    expect(loadConfig(dir).apiKey).toBe("sk-orca-new");
    // Different project dir, no env: file value is used.
    delete process.env.MYTHOS_API_KEY;
    expect(loadConfig(dir).apiKey).toBe("sk-orca-old");
  });

  it("fails with an actionable message when no key is configured (clear)", () => {
    expect(() =>
      createProvider({
        ...structuredClone(DEFAULT_CONFIG),
        provider: "orcarouter",
        apiKey: undefined,
      })
    ).toThrow(/API key required/);
  });

  it("surfaces an upstream 401 with a redacted body", async () => {
    const fetchMock = vi.fn(
      async () => new Response(`{"error":"bad key ${FAKE_KEY}"}`, { status: 401 })
    );
    vi.stubGlobal("fetch", fetchMock);
    try {
      const provider = createProvider(cfg({ provider: "orcarouter" }));
      await expect(provider.chat("sys", [{ role: "user", content: "hi" }])).rejects.toThrow(
        /API error \(401\)/
      );
      const err = await provider
        .chat("sys", [{ role: "user", content: "hi" }])
        .catch((e: Error) => e.message);
      expect(err).not.toContain(FAKE_KEY);
      const [url] = fetchMock.mock.calls[0] as unknown as [string];
      expect(url).toBe(`${ORCAROUTER_API_BASE_URL}/chat/completions`);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
