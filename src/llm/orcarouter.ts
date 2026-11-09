import type { MythosConfig } from "../types/index.js";

/**
 * OrcaRouter Cyber Inference — a named, first-class provider entry.
 *
 * OrcaRouter is an OpenAI-compatible AI gateway that routes many providers
 * behind one endpoint. The "Cyber Inference" entry is the profile mythos-agent
 * exposes for security work: red-team and blue-team users running authorized,
 * scoped security prompts (code review, variant hunting, threat modelling,
 * fix generation) get a named provider with a cyber-tuned default model
 * instead of hand-wiring an arbitrary base URL.
 *
 * - Provider page: https://www.orcarouter.ai/cyber
 * - Cyber-tier model catalog: https://www.orcarouter.ai/models?tier=cyber
 * - Inference / model discovery: https://api.orcarouter.ai/v1
 *
 * Credentials are the user's own OrcaRouter API key (`sk-orca-…`), read from
 * the normal config surfaces (`apiKey:` in `.mythos.yml`, `MYTHOS_API_KEY`
 * env). Nothing here holds or logs a key.
 */

export const ORCAROUTER_PROVIDER_ID = "orcarouter";
export const ORCAROUTER_PROVIDER_LABEL = "OrcaRouter Cyber Inference";
export const ORCAROUTER_API_BASE_URL = "https://api.orcarouter.ai/v1";
/** Inference and model discovery share this origin; auth lives on www.orcarouter.ai. */
export const ORCAROUTER_API_ORIGIN = "https://api.orcarouter.ai";
/** Auth origin (OAuth 2.0 + PKCE consent / key exchange), not used for inference. */
export const ORCAROUTER_AUTH_ORIGIN = "https://www.orcarouter.ai";
export const ORCAROUTER_KEY_DASHBOARD_URL = "https://www.orcarouter.ai/console/keys";
export const ORCAROUTER_PROVIDER_PAGE_URL = "https://www.orcarouter.ai/cyber";
export const ORCAROUTER_CYBER_CATALOG_URL = "https://www.orcarouter.ai/models?tier=cyber";

/** Default model: auto-routing, works with any key. */
export const ORCAROUTER_DEFAULT_MODEL = "orcarouter/auto";
/** General fallback model. */
export const ORCAROUTER_FALLBACK_MODEL = "orcarouter/fusion";

export interface OrcaRouterModelInfo {
  id: string;
  name: string;
  /** Context window in tokens when the catalog reports one. */
  contextWindow?: number;
  /** How the row was obtained: live `/v1/models` or the verified seed. */
  source: "live" | "seed";
}

/**
 * Cyber-tier models recommended to security teams that have completed
 * business verification on OrcaRouter. They are listed first when present in
 * the catalog and are also part of the offline seed so the interactive
 * picker still offers them during a catalog outage.
 */
export const ORCAROUTER_CYBER_MODELS: readonly OrcaRouterModelInfo[] = [
  {
    id: "orcacyber-ultra-1.0",
    name: "OrcaCyber Ultra (security code scanning, large-repo reasoning)",
    source: "seed",
  },
  {
    id: "orcacyber-zero-1.5",
    name: "OrcaCyber Zero (OrcaCyber harness-driven reasoning)",
    source: "seed",
  },
];

/**
 * Small cold-start seed used only when live discovery fails. Kept
 * intentionally tiny; live `/v1/models` is authoritative whenever it
 * responds and the seed is never merged into a live result.
 *
 * Every id here is taken from OrcaRouter's published documentation (the
 * reusable-rules seed in the integration guide plus the cyber-tier model
 * page), not from inspection of a live response or from model-name guessing.
 * The `orcacyber-*` ids are unlocked after OrcaRouter business verification,
 * so a key without that access still sees them but routing reports the
 * upstream error.
 */
export const ORCAROUTER_SEED_MODELS: readonly OrcaRouterModelInfo[] = [
  ...ORCAROUTER_CYBER_MODELS,
  { id: ORCAROUTER_DEFAULT_MODEL, name: "OrcaRouter Auto (auto-routing)", source: "seed" },
  { id: ORCAROUTER_FALLBACK_MODEL, name: "OrcaRouter Fusion (general fallback)", source: "seed" },
  { id: "openai/gpt-5.5", name: "GPT-5.5", source: "seed" },
  { id: "anthropic/claude-opus-4.8", name: "Claude Opus 4.8", source: "seed" },
  { id: "google/gemini-3.5-flash", name: "Gemini 3.5 Flash", source: "seed" },
  { id: "deepseek/deepseek-v4-pro", name: "DeepSeek V4 Pro", source: "seed" },
];

/** Hosts on the shared OrcaRouter deployment (HTTPS enforced for both). */
const ORCAROUTER_HOSTS = new Set(["api.orcarouter.ai", "www.orcarouter.ai"]);

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function isOrcaRouterProvider(provider: string | undefined | null): boolean {
  return provider === ORCAROUTER_PROVIDER_ID;
}

function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname);
}

/**
 * Validate a configured OrcaRouter base URL. Returns the normalised URL
 * (no trailing slash) or throws with an actionable message.
 *
 * Rules: HTTPS for any non-loopback host (self-hosted deployments included);
 * plain HTTP only for loopback development. No userinfo, no query, no
 * fragment. The path must not point at the auth surface — credentials are
 * exchanged at `<auth origin>/api/v1/auth/keys`, never under `/v1` on the
 * inference origin.
 */
export function normalizeOrcaRouterBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(
      `OrcaRouter: invalid base URL "${raw}". Expected e.g. ${ORCAROUTER_API_BASE_URL}`
    );
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`OrcaRouter: base URL must use https:// (got ${url.protocol})`);
  }
  if (url.protocol === "http:" && !isLoopback(url.hostname)) {
    throw new Error(
      `OrcaRouter: http:// is only allowed for loopback hosts; use https:// for ${url.hostname}`
    );
  }
  if (ORCAROUTER_HOSTS.has(url.hostname) && url.protocol !== "https:") {
    throw new Error("OrcaRouter: the public OrcaRouter endpoints require https://");
  }
  if (url.username || url.password) {
    throw new Error("OrcaRouter: base URL must not contain credentials");
  }
  if (url.search || url.hash) {
    throw new Error("OrcaRouter: base URL must not contain a query string or fragment");
  }
  const pathname = url.pathname.replace(/\/+$/, "");
  if (pathname.includes("/auth")) {
    throw new Error(
      "OrcaRouter: auth endpoints are on the auth origin (https://www.orcarouter.ai/api/v1/auth/keys), " +
        "not on the inference base URL; set the inference base URL instead (e.g. /v1)"
    );
  }
  return `${url.origin}${pathname}`;
}

/**
 * Base URL used by the LLM client for an OrcaRouter config. An explicit
 * `baseURL` from config/env wins (pointing it at a self-hosted deployment is
 * the only supported override); otherwise the public API base is used.
 */
export function resolveOrcaRouterBaseUrl(config: Pick<MythosConfig, "baseURL">): string {
  if (config.baseURL && config.baseURL.trim().length > 0) {
    return normalizeOrcaRouterBaseUrl(config.baseURL.trim());
  }
  return ORCAROUTER_API_BASE_URL;
}

/** True when the configured key looks like an OrcaRouter key (`sk-orca-…`). */
export function looksLikeOrcaRouterKey(key: string | undefined | null): boolean {
  return typeof key === "string" && key.startsWith("sk-orca-");
}

/** Mask a secret for display / logs. Never returns the full key. */
export function maskSecret(secret: string | undefined | null): string {
  if (!secret) return "(not set)";
  if (secret.length <= 12) return "****";
  // Keep only the scheme prefix ("sk-orca") and the last four characters.
  const prefixEnd = secret.indexOf("-", 3);
  const prefix = prefixEnd > 0 && prefixEnd < 10 ? secret.slice(0, prefixEnd) : secret.slice(0, 4);
  return `${prefix}-…${secret.slice(-4)}`;
}
