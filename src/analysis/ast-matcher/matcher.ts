import { getParser, type SupportedLanguage } from "./parser.js";

/**
 * AST-based pattern matcher (sub-PR A2 of variants v2 — see
 * docs/path-forward.md Track A).
 *
 * A1 produces a `RootCausePattern` whose `astShape` field describes
 * the vulnerable code as a top-level node `kind` plus a list of
 * human-readable `constraints`. A2 turns that schema into actionable
 * search: given a `kind` and (optionally) a list of regex predicates
 * to apply to the matched node's source text, walk the parsed AST
 * and return every node that satisfies the query.
 *
 * Design choices:
 *
 *  - **Kind union, not a query DSL.** `kind` accepts a single string
 *    or an array of strings (matched against `node.type`). A1's
 *    seed-patterns.ts already uses union-shaped kinds for two of the
 *    five CVEs (`regex_or_template_literal`, `object_or_array_literal`)
 *    and treating these as `[kindA, kindB]` is cheaper than building
 *    a real query DSL. A real DSL (ast-grep YAML / tree-sitter
 *    queries) is a candidate for A2.x once we know which constraints
 *    repeat across the seed corpus — premature for v1.
 *
 *  - **Text predicates are regexes against `node.text`.** A1's
 *    `astShape.constraints` are prose like "list contains
 *    'authorization'"; the agent loop translates each prose
 *    constraint into a regex (e.g. `/authorization/i`) and passes
 *    them in as `textPredicates`. This puts the burden of
 *    constraint-to-regex translation on the LLM caller, which is
 *    acceptable for v1: the agent already does similar prose-to-
 *    pattern translation in `search_code`. A future A2.x can add
 *    structural constraints (kind/depth/sibling predicates) once
 *    we observe which textual predicates aren't expressive enough.
 *
 *  - **Iterative DFS, not a query.** tree-sitter has a built-in
 *    Query API that compiles a Scheme-like S-expression query
 *    against a tree, and it's faster than userland walking. We
 *    don't use it because:
 *    1. The Query API rejects unknown node kinds at compile time;
 *       a typo in A1's seed `astShape.kind` would surface as a
 *       runtime error far from the seed file rather than a quiet
 *       no-match. Walking is more forgiving and easier to debug
 *       at v1.
 *    2. The Query API's text-predicate dialect (`#match?`) doesn't
 *       round-trip cleanly with JS regex flags. Doing predicates
 *       in JS keeps the regex contract identical to `search_code`.
 *
 *  - **Match cap.** A query that matches too broadly (e.g.
 *    `kind: "identifier"` with no predicates) would walk the whole
 *    tree and return thousands of nodes. We cap at `maxMatches`
 *    (default 200) to keep the agent's tool-result payload
 *    bounded; the LLM gets a deterministic truncation message
 *    rather than a 50KB result block that gets context-trimmed.
 */

export interface FindAstPatternOptions {
  /**
   * tree-sitter node kind to match. Pass an array to match any of
   * several kinds (union semantics).
   */
  kind: string | string[];
  /** Source code to parse. */
  source: string;
  /** Language to parse `source` as. */
  language: SupportedLanguage;
  /**
   * Optional list of regex strings; a node matches only if EVERY
   * predicate's regex matches the node's text. Each entry is
   * compiled with `new RegExp(predicate, "u")`; pass case-insensitive
   * patterns inline as `(?i)` is not supported, instead use
   * `[Aa][Uu]...` or accept the agent's case-correct output.
   */
  textPredicates?: string[];
  /**
   * Maximum number of matches to return before truncating. Default
   * 200 — large enough to surface every realistic hit, small enough
   * that the agent's tool-result payload stays bounded.
   */
  maxMatches?: number;
}

export interface AstMatch {
  /** tree-sitter node kind that was matched. */
  kind: string;
  /** Source-text slice of the matched node. */
  text: string;
  /** 1-based start line. */
  startLine: number;
  /** 1-based end line. */
  endLine: number;
  /** 0-based start column. */
  startColumn: number;
  /** 0-based end column. */
  endColumn: number;
}

const DEFAULT_MAX_MATCHES = 200;
/**
 * Hard cap on per-node text length passed to predicates. A long
 * function body could be tens of KB; running 5 regexes against it
 * for every node is wasteful when the agent's text predicates are
 * almost always going to look at the first ~8KB. Larger nodes are
 * still returned (kind/location info), just with predicates evaluated
 * over the truncated text.
 */
const PREDICATE_TEXT_CAP = 8192;

export async function findAstPattern(opts: FindAstPatternOptions): Promise<AstMatch[]> {
  const kinds = Array.isArray(opts.kind) ? new Set(opts.kind) : new Set([opts.kind]);
  const predicates = (opts.textPredicates ?? []).map((p) => new RegExp(p, "u"));
  const maxMatches = opts.maxMatches ?? DEFAULT_MAX_MATCHES;

  const parser = await getParser(opts.language);
  const tree = parser.parse(opts.source);
  if (!tree) return [];

  const matches: AstMatch[] = [];
  const stack = [tree.rootNode];
  while (stack.length > 0 && matches.length < maxMatches) {
    const node = stack.pop();
    if (!node) continue;

    if (kinds.has(node.type)) {
      const text = node.text;
      const probe = text.length > PREDICATE_TEXT_CAP ? text.slice(0, PREDICATE_TEXT_CAP) : text;
      const allMatch = predicates.every((re) => re.test(probe));
      if (allMatch) {
        matches.push({
          kind: node.type,
          text,
          startLine: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          startColumn: node.startPosition.column,
          endColumn: node.endPosition.column,
        });
      }
    }

    // Push children in reverse so DFS visits them left-to-right.
    for (let i = node.childCount - 1; i >= 0; i--) {
      const child = node.child(i);
      if (child) stack.push(child);
    }
  }

  return matches;
}

export { inferLanguage } from "./parser.js";
export type { SupportedLanguage } from "./parser.js";
