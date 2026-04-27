import fs from "node:fs";
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
 * Grammar-directory resolution (see `findGrammarsDir` below):
 *  - The naive `path.resolve(__dirname, "../../../assets/grammars")`
 *    works when the module is at `src/analysis/ast-matcher/parser.ts`
 *    or `dist/analysis/ast-matcher/parser.js` — both layouts have the
 *    same depth from `assets/grammars` at the repo root. It DOES NOT
 *    work when the module is compiled to `dist-benchmarks/src/...`
 *    (the benchmark tsconfig preserves the `src/` prefix), where the
 *    fixed hop count lands on `dist-benchmarks/assets/grammars/`,
 *    which doesn't exist.
 *  - This silent miss surfaced in the A3b calibration runs as the
 *    agent reporting *"The AST engine has file access issues"* and
 *    falling back to regex search — defeating the whole point of
 *    sub-PR A2. Walking up looking for `assets/grammars` in a parent
 *    is robust to any compiled layout that keeps the bundle a peer
 *    or descendant of the repo root.
 *
 * Test ergonomics: `resetParserForTesting()` lets tests reset the
 * cached state between cases when they need to verify init/load
 * behavior. Production code never calls it.
 */

export type SupportedLanguage = "javascript" | "typescript";

/**
 * Walk up from `start` looking for an `assets/grammars` directory.
 * Returns the first one found. Throws if none exists by the time we
 * hit the filesystem root — callers convert that into the user-facing
 * "wasm files weren't bundled" error inside `loadLanguage`, where it
 * has the language id as additional context.
 *
 * Exported for direct testing — verifying the walk-up against synthetic
 * directory layouts is much cleaner than mocking `import.meta.url`.
 */
export function findGrammarsDir(start: string): string {
  let dir = start;
  while (dir !== path.dirname(dir)) {
    const candidate = path.join(dir, "assets", "grammars");
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(
    `Could not locate assets/grammars/ walking up from ${start}. ` +
      `Tree-sitter grammar wasm files must be reachable from a parent ` +
      `directory of the parser module — see assets/grammars/README.md ` +
      `in the mythos-agent repo for the expected layout.`
  );
}

let cachedGrammarsDir: string | null = null;
function getGrammarsDir(): string {
  if (cachedGrammarsDir === null) {
    cachedGrammarsDir = findGrammarsDir(path.dirname(fileURLToPath(import.meta.url)));
  }
  return cachedGrammarsDir;
}

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
    const grammarPath = path.join(getGrammarsDir(), GRAMMAR_FILES[language]);
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
 * Test-only: clear the init promise, language cache, and resolved
 * grammars directory. Production code never calls this. Tests use it
 * to verify cold-start behavior or to recover from a `Language.load`
 * rejection without polluting subsequent test cases.
 */
export function resetParserForTesting(): void {
  initPromise = null;
  languageCache.clear();
  cachedGrammarsDir = null;
}
