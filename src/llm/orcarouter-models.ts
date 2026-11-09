import {
  ORCAROUTER_API_BASE_URL,
  ORCAROUTER_SEED_MODELS,
  ORCAROUTER_CYBER_MODELS,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_FALLBACK_MODEL,
  isOrcaRouterProvider,
  normalizeOrcaRouterBaseUrl,
  ORCAROUTER_PROVIDER_ID,
  type OrcaRouterModelInfo,
} from "./orcarouter.js";

/**
 * Model discovery for the OrcaRouter provider.
 *
 * `GET {base}/models` is the single source of truth for which models the
 * user's key can actually call. The response is bounded (timeout, byte cap,
 * item cap) so a slow or hostile catalog cannot hang a scan or exhaust
 * memory, and only chat-capable entries that declare an endpoint type the
 * OpenAI SDK can speak are kept. When the request fails, a small verified
 * seed is returned with `degraded: true` so the CLI can say so explicitly —
 * the seed never gets mixed into a successful live result.
 */

export type ModelDiscoveryStatus = "ok" | "auth_error" | "network_error" | "empty";

export interface ModelDiscoveryResult {
  models: OrcaRouterModelInfo[];
  /** Where the list came from. `seed` means live discovery failed. */
  source: "live" | "seed";
  status: ModelDiscoveryStatus;
  degraded: boolean;
  /** Present when `degraded` — redacted, human-readable reason. */
  error?: string;
}

export interface ModelDiscoveryOptions {
  apiKey?: string;
  baseURL?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxBytes?: number;
  maxItems?: number;
}

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_ITEMS = 500;

/** Endpoint types the OpenAI SDK code path can talk to. */
const TEXT_ENDPOINT_TYPES = new Set(["openai", "anthropic", "gemini", "openai-response"]);

/** Endpoint types that are explicitly not text chat (never in the text picker). */
const NON_TEXT_ENDPOINT_TYPES = new Set(["image-generation", "openai-video", "jina-rerank"]);

interface RawCatalogModel {
  id?: unknown;
  name?: unknown;
  context_length?: unknown;
  context_window?: unknown;
  supported_endpoint_types?: unknown;
  endpoint_types?: unknown;
  architecture?: { output_modalities?: unknown } | null;
}

/**
 * Decide whether a catalog row is a text chat route the OpenAI SDK can call.
 * Fail closed: a row with no recognised endpoint types and no evidence of
 * being a text chat model is dropped.
 */
export function isChatCapableModel(raw: RawCatalogModel): boolean {
  if (typeof raw.id !== "string" || raw.id.trim().length === 0) return false;
  const declared = raw.supported_endpoint_types ?? raw.endpoint_types;
  const types = Array.isArray(declared)
    ? declared.filter((t): t is string => typeof t === "string")
    : [];
  if (types.length > 0) {
    if (types.some((t) => NON_TEXT_ENDPOINT_TYPES.has(t))) return false;
    return types.some((t) => TEXT_ENDPOINT_TYPES.has(t));
  }
  const outputs = raw.architecture?.output_modalities;
  if (Array.isArray(outputs) && outputs.length > 0) {
    return outputs.length === 1 && outputs[0] === "text";
  }
  // No capability metadata: only trust namespaced `vendor/model` ids (the
  // OrcaRouter catalog shape) rather than guessing from names.
  return /^[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._:-]*$/i.test(raw.id.trim());
}

function contextWindowOf(raw: RawCatalogModel): number | undefined {
  for (const candidate of [raw.context_length, raw.context_window]) {
    if (typeof candidate === "number" && Number.isFinite(candidate) && candidate > 0) {
      return candidate;
    }
  }
  return undefined;
}

/** Parse a `/models` payload into bounded, filtered model metadata. */
export function parseModelCatalog(
  payload: unknown,
  maxItems = DEFAULT_MAX_ITEMS
): OrcaRouterModelInfo[] {
  const data =
    payload && typeof payload === "object" && Array.isArray((payload as { data?: unknown }).data)
      ? ((payload as { data: unknown[] }).data as RawCatalogModel[])
      : [];
  const seen = new Set<string>();
  const models: OrcaRouterModelInfo[] = [];
  for (const raw of data) {
    if (models.length >= maxItems) break;
    if (!raw || typeof raw !== "object") continue;
    if (!isChatCapableModel(raw)) continue;
    const id = (raw.id as string).trim();
    if (seen.has(id)) continue;
    seen.add(id);
    models.push({
      id,
      name: typeof raw.name === "string" && raw.name.trim() ? raw.name.trim() : id,
      contextWindow: contextWindowOf(raw),
      source: "live",
    });
    // Cyber-tier rows present in the live catalog float to the top (see
    // orderModelsForSecurityWork) so the picker's first screen is useful.
    if (models.length === maxItems) break;
  }
  return orderModelsForSecurityWork(models);
}

/** Cyber-tier models first (when present), then default, then the rest. */
function orderModelsForSecurityWork(models: OrcaRouterModelInfo[]): OrcaRouterModelInfo[] {
  const rank = (m: OrcaRouterModelInfo): number => {
    const cyberIndex = ORCAROUTER_CYBER_MODELS.findIndex((c) => c.id === m.id);
    if (cyberIndex >= 0) return cyberIndex;
    if (m.id === ORCAROUTER_DEFAULT_MODEL) return 100;
    if (m.id === ORCAROUTER_FALLBACK_MODEL) return 101;
    return 1000;
  };
  return models
    .map((m, i) => ({ m, i }))
    .sort((a, b) => rank(a.m) - rank(b.m) || a.i - b.i)
    .map(({ m }) => m);
}

/** Verified offline seed, preserving cyber-tier → default → fallback order. */
export function seedModels(): OrcaRouterModelInfo[] {
  return ORCAROUTER_SEED_MODELS.map((m) => ({ ...m }));
}

function redact(text: string, apiKey?: string): string {
  let out = text.replace(/Bearer\s+[A-Za-z0-9._\-+/=]+/gi, "Bearer ***");
  if (apiKey && apiKey.length > 4) out = out.split(apiKey).join("***");
  return out.slice(0, 300);
}

/**
 * Discover the OrcaRouter chat catalog. Never throws: failures return the
 * verified seed with `degraded: true` and a classified status.
 */
export async function discoverOrcaRouterModels(
  options: ModelDiscoveryOptions = {}
): Promise<ModelDiscoveryResult> {
  const base = options.baseURL
    ? normalizeOrcaRouterBaseUrl(options.baseURL)
    : ORCAROUTER_API_BASE_URL;
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxItems = options.maxItems ?? DEFAULT_MAX_ITEMS;

  const degraded = (status: ModelDiscoveryStatus, error: string): ModelDiscoveryResult => ({
    models: seedModels(),
    source: "seed",
    status,
    degraded: true,
    error: redact(error, options.apiKey),
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = `${base}/models?capability=chat`;
    const headers: Record<string, string> = { Accept: "application/json" };
    if (options.apiKey) headers.Authorization = `Bearer ${options.apiKey}`;

    const response = await fetchImpl(url, { method: "GET", headers, signal: controller.signal });
    if (!response.ok) {
      const status: ModelDiscoveryStatus =
        response.status === 401 || response.status === 403 ? "auth_error" : "network_error";
      let body = "";
      try {
        body = (await response.text()).slice(0, 300);
      } catch {
        body = "";
      }
      return degraded(status, `HTTP ${response.status} from ${url}${body ? `: ${body}` : ""}`);
    }

    const reader = response.body?.getReader();
    let text: string;
    if (reader) {
      const chunks: Uint8Array[] = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > maxBytes) {
            await reader.cancel().catch(() => undefined);
            return degraded("network_error", `model catalog exceeded ${maxBytes} bytes`);
          }
          chunks.push(value);
        }
      }
      text = Buffer.concat(chunks).toString("utf-8");
    } else {
      text = await response.text();
      if (Buffer.byteLength(text) > maxBytes) {
        return degraded("network_error", `model catalog exceeded ${maxBytes} bytes`);
      }
    }

    let payload: unknown;
    try {
      payload = JSON.parse(text);
    } catch {
      return degraded("network_error", "model catalog was not valid JSON");
    }

    const models = parseModelCatalog(payload, maxItems);
    if (models.length === 0) {
      return degraded("empty", "model catalog returned no chat-capable models");
    }
    return { models, source: "live", status: "ok", degraded: false };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const timedOut = err instanceof Error && err.name === "AbortError";
    return degraded("network_error", timedOut ? `timeout after ${timeoutMs} ms` : message);
  } finally {
    clearTimeout(timer);
  }
}

/** Provider ids that get OrcaRouter discovery instead of a static list. */
export function providerUsesOrcaRouterCatalog(provider: string | undefined): boolean {
  return isOrcaRouterProvider(provider) || provider === ORCAROUTER_PROVIDER_ID;
}
