import { describe, it, expect } from "vitest";
import {
  ORCAROUTER_API_BASE_URL,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_PROVIDER_LABEL,
  isOrcaRouterProvider,
  looksLikeOrcaRouterKey,
  maskSecret,
  normalizeOrcaRouterBaseUrl,
  resolveOrcaRouterBaseUrl,
} from "../orcarouter.js";
import { createLLMClient, resolveModelForProvider } from "../index.js";
import { OpenAILLMClient } from "../openai-client.js";
import { AnthropicLLMClient } from "../anthropic-client.js";
import { DEFAULT_CONFIG, type MythosConfig } from "../../types/index.js";

const FAKE_KEY = "sk-orca-test-000000000000000000000000";

function cfg(overrides: Partial<MythosConfig> = {}): MythosConfig {
  return { ...structuredClone(DEFAULT_CONFIG), apiKey: FAKE_KEY, ...overrides };
}

describe("OrcaRouter provider identity", () => {
  it("is a named provider with the cyber-tier label and public API base", () => {
    expect(isOrcaRouterProvider("orcarouter")).toBe(true);
    expect(isOrcaRouterProvider("openai")).toBe(false);
    expect(isOrcaRouterProvider(undefined)).toBe(false);
    expect(ORCAROUTER_PROVIDER_LABEL).toBe("OrcaRouter Cyber Inference");
    expect(ORCAROUTER_API_BASE_URL).toBe("https://api.orcarouter.ai/v1");
  });

  it("recognises only the sk-orca- key prefix as a format hint", () => {
    expect(looksLikeOrcaRouterKey(FAKE_KEY)).toBe(true);
    expect(looksLikeOrcaRouterKey("sk-openai")).toBe(false);
    expect(looksLikeOrcaRouterKey(undefined)).toBe(false);
  });

  it("masks secrets without revealing the middle of the key", () => {
    const masked = maskSecret(FAKE_KEY);
    expect(masked).not.toBe(FAKE_KEY);
    expect(masked).not.toContain("test-0000");
    expect(masked.startsWith("sk-orca")).toBe(true);
    expect(maskSecret("short")).toBe("****");
    expect(maskSecret(undefined)).toBe("(not set)");
  });
});

describe("base URL policy", () => {
  it("requires https for the public endpoints", () => {
    expect(normalizeOrcaRouterBaseUrl("https://api.orcarouter.ai/v1/")).toBe(
      "https://api.orcarouter.ai/v1"
    );
    expect(() => normalizeOrcaRouterBaseUrl("http://api.orcarouter.ai/v1")).toThrow(/https/);
  });

  it("allows http only for loopback self-hosted deployments", () => {
    expect(normalizeOrcaRouterBaseUrl("http://127.0.0.1:8080/v1")).toBe("http://127.0.0.1:8080/v1");
    expect(normalizeOrcaRouterBaseUrl("http://localhost:8080/v1")).toBe("http://localhost:8080/v1");
    expect(() => normalizeOrcaRouterBaseUrl("http://orcarouter.internal/v1")).toThrow(/loopback/);
  });

  it("rejects the common auth-path mistake and userinfo/query/fragment", () => {
    expect(() => normalizeOrcaRouterBaseUrl("https://api.orcarouter.ai/v1/auth/keys")).toThrow(
      /auth origin/
    );
    expect(() => normalizeOrcaRouterBaseUrl("https://user:pw@api.orcarouter.ai/v1")).toThrow(
      /credentials/
    );
    expect(() => normalizeOrcaRouterBaseUrl("https://api.orcarouter.ai/v1?x=1")).toThrow(/query/);
    expect(() => normalizeOrcaRouterBaseUrl("not a url")).toThrow(/invalid/);
  });

  it("uses the API base by default and an explicit override when set", () => {
    expect(resolveOrcaRouterBaseUrl({})).toBe(ORCAROUTER_API_BASE_URL);
    expect(resolveOrcaRouterBaseUrl({ baseURL: "https://orca.self-host.example/v1" })).toBe(
      "https://orca.self-host.example/v1"
    );
  });
});

describe("createLLMClient routing", () => {
  it("routes orcarouter through the OpenAI adapter pinned to api.orcarouter.ai/v1", () => {
    const client = createLLMClient(cfg({ provider: "orcarouter" }));
    expect(client).toBeInstanceOf(OpenAILLMClient);
    // The adapter's inner SDK must have the OrcaRouter base URL, not OpenAI's.
    const inner = (client as unknown as { inner: { baseURL: string } }).inner;
    expect(inner.baseURL).toBe(ORCAROUTER_API_BASE_URL);
  });

  it("keeps anthropic on Tier 1 and unknown providers on the OpenAI default", () => {
    expect(createLLMClient(cfg({ provider: "anthropic" }))).toBeInstanceOf(AnthropicLLMClient);
    const other = createLLMClient(cfg({ provider: "custom" }));
    expect(other).toBeInstanceOf(OpenAILLMClient);
  });

  it("honours an explicit self-hosted override but nothing implicit", () => {
    const client = createLLMClient(
      cfg({ provider: "orcarouter", baseURL: "https://orca.example.net/v1" })
    );
    const inner = (client as unknown as { inner: { baseURL: string } }).inner;
    expect(inner.baseURL).toBe("https://orca.example.net/v1");
  });

  it("rejects an invalid override before any request is made", () => {
    expect(() =>
      createLLMClient(cfg({ provider: "orcarouter", baseURL: "http://api.orcarouter.ai/v1" }))
    ).toThrow(/https/);
  });
});

describe("resolveModelForProvider", () => {
  it("defaults orcarouter to the auto-routing model when unset or anthropic-shaped", () => {
    expect(resolveModelForProvider(cfg({ provider: "orcarouter", model: "" }))).toBe(
      ORCAROUTER_DEFAULT_MODEL
    );
    expect(resolveModelForProvider(cfg({ provider: "orcarouter" }))).toBe(ORCAROUTER_DEFAULT_MODEL);
  });

  it("preserves vendor/model namespaces verbatim", () => {
    expect(
      resolveModelForProvider(cfg({ provider: "orcarouter", model: "orcacyber-ultra-1.0" }))
    ).toBe("orcacyber-ultra-1.0");
    expect(
      resolveModelForProvider(cfg({ provider: "orcarouter", model: "orcarouter/fusion" }))
    ).toBe("orcarouter/fusion");
  });

  it("leaves other providers untouched", () => {
    expect(resolveModelForProvider(cfg({ provider: "anthropic" }))).toBe(DEFAULT_CONFIG.model);
    expect(resolveModelForProvider(cfg({ provider: "openai", model: "" }))).toBe("");
  });
});
