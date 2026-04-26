import type { RootCausePattern } from "./types.js";

/**
 * Hand-curated root-cause patterns for the 5 CVEs in the existing
 * CVE Replay corpus (`benchmarks/cve-replay/cases/`).
 *
 * These serve three roles:
 *
 *  1. **LLM-prior / few-shot examples.** When the extractor is asked
 *     about a non-seeded CVE it prepends a subset of these to the
 *     prompt as concrete examples of the schema.
 *  2. **Calibration ground truth.** Sub-PR A3 of Track A uses these
 *     as the targets the AST matcher must hit. If A2's matcher can
 *     produce any of these patterns and find the actual fix-commit
 *     code, the design is working. If not, A3's kill criterion
 *     fires (see docs/path-forward.md).
 *  3. **Deterministic fallback.** If the LLM is unavailable or
 *     returns malformed output for one of these 5, the extractor
 *     returns the seed instead of `null`. Keeps the calibration
 *     corpus reproducible across model swaps.
 *
 * Authority: each entry below was hand-derived by reading the
 * upstream fix commit (or a CVE write-up linking to it) and the case
 * file's `notes` field. Do not regenerate these from an LLM — they
 * are the ground truth the LLM is being calibrated against.
 *
 * Lookup is keyed by both CVE id and GHSA id; either works.
 */
const SEEDS: RootCausePattern[] = [
  {
    cveId: "CVE-2021-23337",
    ghsaId: "GHSA-35jh-r3h4-6jhm",
    bugClass: "template-code-injection",
    cwe: "CWE-94",
    languages: ["javascript", "typescript"],
    astShape: {
      kind: "call_expression",
      constraints: [
        "callee resolves to lodash `template` (member expression `_.template` or named import `template`)",
        "second-argument options object propagates into a `Function()` constructor call inside the template runtime",
        "options object reaches the call site without sanitization",
      ],
    },
    dataFlow: {
      source: "attacker-controlled `options` argument to `_.template(text, options)`",
      sink: "`Function(...)` constructor evaluating the option values as JS source",
      propagation:
        "options.sourceURL / options.variable are interpolated into the generated compiled template before it is passed to `Function()`",
    },
    summary:
      "lodash's `template()` evaluates option values as code via the `Function()` constructor; when the options object is attacker-controlled, the attacker gains arbitrary JS execution in the template-rendering process.",
  },
  {
    cveId: "CVE-2024-45296",
    ghsaId: "GHSA-9wv6-86v2-598j",
    bugClass: "redos-dynamic-regex",
    cwe: "CWE-1333",
    languages: ["javascript", "typescript"],
    astShape: {
      kind: "new_expression",
      constraints: [
        "constructor identifier is `RegExp`",
        "first argument is built by string concatenation or template literals from a function parameter",
        "the assembled pattern contains nested or adjacent unbounded quantifiers (`(.+)+`, `(.*?)+`, `[^/]*`)",
      ],
    },
    dataFlow: {
      source: "caller-supplied path-pattern string passed to `pathToRegexp(path)`",
      sink: "`new RegExp(pattern)` whose backtracking complexity is exponential on certain inputs",
      propagation:
        "path segments are split, each segment's regex fragment is concatenated into a master pattern that is then compiled at request time",
    },
    summary:
      "path-to-regexp constructs a regex dynamically from caller-supplied path patterns; for crafted patterns the resulting regex backtracks catastrophically on adversarial path strings, yielding a denial-of-service.",
  },
  {
    cveId: "CVE-2022-25883",
    ghsaId: "GHSA-c2qf-rxjj-qqgw",
    bugClass: "redos-static-template-regex",
    cwe: "CWE-1333",
    languages: ["javascript", "typescript"],
    astShape: {
      kind: "regex_or_template_literal",
      constraints: [
        "regex literal or `new RegExp(`...`)` whose source contains an unbounded whitespace class (`\\s*` or `\\s+`)",
        "the unbounded class is adjacent to a `${}` interpolation slot in a template literal that builds the regex source",
        "the compiled regex is later invoked via `RegExp.prototype.test` or `String.prototype.match` against attacker-influenced input",
      ],
    },
    dataFlow: {
      source:
        "version-range string from user input (e.g. semver range field on an npm install request)",
      sink: "`re.test(rangeString)` where `re` was built from the vulnerable template",
      propagation:
        "the static template is compiled once at module load; subsequent `.test()` calls trigger the catastrophic-backtracking path on whitespace-padded input",
    },
    summary:
      "node-semver's range regex (in `internal/re.js`) is built from a template literal with `\\s*` immediately adjacent to a `${}` interpolation; on long whitespace-padded version strings the regex engine backtracks for seconds, producing a CPU-bound DoS in callers that accept user-supplied ranges.",
  },
  {
    cveId: "CVE-2024-28849",
    ghsaId: "GHSA-cxjh-pqwp-8mfp",
    bugClass: "incomplete-redirect-header-strip",
    cwe: "CWE-200",
    languages: ["javascript", "typescript"],
    astShape: {
      kind: "object_or_array_literal",
      constraints: [
        "literal listing HTTP header names to strip on cross-origin redirect",
        "list contains `authorization` and/or `cookie` (case-insensitive)",
        "list omits `proxy-authorization`",
        "the literal is consumed by a redirect-handler code path (function or method whose name contains `redirect`)",
      ],
    },
    dataFlow: {
      source: "redirect `Location` header pointing at an attacker-controlled origin",
      sink: "outbound HTTP request to the redirected origin that still carries the original `Proxy-Authorization` header",
      propagation:
        "the redirect handler removes Authorization/Cookie from the carried-over header set but never deletes Proxy-Authorization, so the proxy credential is forwarded to whatever third-party host the attacker redirects to",
    },
    summary:
      "follow-redirects strips `Authorization` and `Cookie` headers when following a cross-origin redirect but does not strip `Proxy-Authorization`, so an attacker who controls the redirect target can harvest the victim's proxy credentials.",
  },
  {
    cveId: "CVE-2022-23541",
    ghsaId: "GHSA-hjrf-2m68-5959",
    bugClass: "jwt-algorithm-key-confusion",
    cwe: "CWE-287",
    languages: ["javascript", "typescript"],
    astShape: {
      kind: "function_declaration",
      constraints: [
        "function accepts a parameter named `secretOrPublicKey` (or equivalent dual-purpose binding)",
        "function dispatches to an HMAC verify path when the JWT header `alg` is HS256/HS384/HS512",
        "no precondition asserts that the supplied key's `type` is `'secret'` (i.e. it accepts a key whose `type` is `'public'` for HMAC)",
      ],
    },
    dataFlow: {
      source: "caller-supplied `secretOrPublicKey` argument to `jwt.verify`",
      sink: "HMAC verify path that uses the (public) key as a shared secret",
      propagation:
        "an attacker who knows the verifier's public key can mint HS256 tokens signed with that public key as the HMAC secret; the verify path accepts them",
    },
    summary:
      "jsonwebtoken's verify path accepts a public key as the HMAC secret when the JWT header advertises an HMAC algorithm; an attacker who knows the verifier's public key (often distributed openly for asymmetric verification) can forge HS256-signed tokens and pass authentication.",
  },
];

/**
 * Normalize an id into the canonical form used as the lookup key.
 * Accepts both `CVE-...` and `GHSA-...` ids in any case.
 */
function canonicalize(id: string): string {
  return id.trim().toUpperCase();
}

const BY_ID = new Map<string, RootCausePattern>();
for (const seed of SEEDS) {
  BY_ID.set(canonicalize(seed.cveId), seed);
  if (seed.ghsaId) BY_ID.set(canonicalize(seed.ghsaId), seed);
}

/** Look up a seeded pattern by CVE or GHSA id. Returns `null` if not seeded. */
export function getSeedPattern(id: string): RootCausePattern | null {
  return BY_ID.get(canonicalize(id)) ?? null;
}

/**
 * All seed patterns. Iteration order follows the CVE Replay case
 * filenames (alphabetical by GHSA id) so the test assertion below
 * stays diff-stable.
 */
export const SEED_PATTERNS: readonly RootCausePattern[] = SEEDS;

/** Set of canonicalized ids that have a seed (CVE and GHSA both included). */
export const SEEDED_IDS: ReadonlySet<string> = new Set(BY_ID.keys());
