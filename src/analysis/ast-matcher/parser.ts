import path from "node:path";
import { fileURLToPath } from "node:url";
import { Parser, Language } from "web-tree-sitter";

/**
 * Lazy parser singleton for sub-PR A2 of variants v2 (see
 * docs/path-forward.md Track A and the A1 module at
 * src/analysis/root-cause/).
 *
 * web-tree-sitter is a WASM build of tree-sitter; it requires a
 * one-time `Parser.init()` to bring up the Emscripten runtime, then
 * lazy `Language.load(<path-to-grammar>.wasm)` for each language.
 * Both are async and slow enough that we cache them — a typical
 * mythos-agent run parses dozens of files of the same language back-
 * to-back, so the per-language `Language` object should be loaded
 * exactly once per process.
 *
 * Why a module-level singleton (rather than a class instance):
 *  - `Parser.init()` mutates global Emscripten state; calling it
 *    twice is wasteful and the second call's promise just resolves
 *    immediately, but the API surface is cleaner if callers don't
 *    have to plumb a Parser instance through several layers.
 *  - The grammar `.wasm` files are static assets, not config; there's
 *    no scenario where two parts of the codebase want different
 *    grammar bundles in the same process.
 *
 * Test ergonomics: `resetParserForTesting()` lets tests reset the
 * cached state between cases when they need to verify init/load
 * behavior. Production code never calls it.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GRAMMARS_DIR = path.resolve(__dirname, "../../../assets/grammars");

export type SupportedLanguage = "javascript" | "typescript";

const GRAMMAR_FILES: Record<SupportedLanguage, string> = {
  javascript: "tree-sitter-javascript.wasm",
  typescript: "tree-sitter-typescript.wasm",
};

let initPromise: Promise<void> | null = null;
const languageCache = new Map<SupportedLanguage, Promise<Language>>();

async function ensureInit(): Promise<void> {
  if (!initPromise) initPromise = Parser.init();
  return initPromise;
}

async function loadLanguage(language: SupportedLanguage): Promise<Language> {
  const cached = languageCache.get(language);
  if (cached) return cached;
  const promise = (async () => {
    await ensureInit();
    const grammarPath = path.join(GRAMMARS_DIR, GRAMMAR_FILES[language]);
    return Language.load(grammarPath);
  })();
  languageCache.set(language, promise);
  return promise;
}

/**
 * Get a Parser configured for the given language. The Parser instance
 * itself is cheap to allocate; the expensive part (WASM init + grammar
 * load) is cached. Callers may use the returned parser concurrently
 * for multiple parses of the same language.
 */
export async function getParser(language: SupportedLanguage): Promise<Parser> {
  const lang = await loadLanguage(language);
  const parser = new Parser();
  parser.setLanguage(lang);
  return parser;
}

/**
 * Infer the parser language from a file path's extension. Returns
 * `null` for unsupported extensions so the caller can skip the file
 * rather than parse it as the wrong language. The set is intentionally
 * conservative — A2 covers JS/TS only because all 5 CVEs in the
 * existing CVE Replay corpus are npm packages. Adding Python / Go /
 * Java grammars is a follow-up that should ship with seed CVEs in
 * those ecosystems, otherwise we'd be testing parser plumbing without
 * any matchers exercising it.
 */
export function inferLanguage(filePath: string): SupportedLanguage | null {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".ts":
    case ".tsx":
    case ".cts":
    case ".mts":
      return "typescript";
    case ".js":
    case ".jsx":
    case ".cjs":
    case ".mjs":
      return "javascript";
    default:
      return null;
  }
}

/**
 * Test-only: clear the init promise and language cache. Production
 * code never calls this. Tests use it to verify cold-start behavior
 * or to recover from a `Language.load` rejection without polluting
 * subsequent test cases.
 */
export function resetParserForTesting(): void {
  initPromise = null;
  languageCache.clear();
}
