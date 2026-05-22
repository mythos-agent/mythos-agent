import type { RootCausePattern } from "./types.js";

/**
 * Hand-curated root-cause patterns for variants v2.
 *
 * The corpus has two tiers:
 *
 *  - **Tier 1 — the 5 calibration-corpus seeds.** These cover the 5
 *    CVEs in the CVE Replay corpus (`benchmarks/cve-replay/cases/`)
 *    and are the calibration ground truth for sub-PR A3 of Track A.
 *  - **Tier 2 — the 6 bug-class-coverage seeds.** Six additional
 *    seeds (prototype pollution, OS command injection, path
 *    traversal, SSRF, SQL injection, XXE) broaden the variant-hunt
 *    seed corpus beyond the CVE Replay cases. They are not paired
 *    with a CVE Replay case file, so the calibration runner skips
 *    them (no `calibration_target`); their correctness is gated by
 *    the offline matcher checks in
 *    `__tests__/seed-patterns.test.ts` instead.
 *
 * These serve three roles:
 *
 *  1. **LLM-prior / few-shot examples.** When the extractor is asked
 *     about a non-seeded CVE it prepends a subset of these to the
 *     prompt as concrete examples of the schema.
 *  2. **Calibration ground truth.** Sub-PR A3 of Track A uses the
 *     Tier 1 seeds as the targets the AST matcher must hit. If A2's
 *     matcher can produce any of these patterns and find the actual
 *     fix-commit code, the design is working. If not, A3's kill
 *     criterion fires (see docs/path-forward.md).
 *  3. **Deterministic fallback.** If the LLM is unavailable or
 *     returns malformed output for one of these CVEs, the extractor
 *     returns the seed instead of `null`. Keeps the calibration
 *     corpus reproducible across model swaps.
 *
 * Authority: each entry below was hand-derived by reading the
 * upstream fix commit (or a CVE write-up linking to it) and, for
 * Tier 1, the case file's `notes` field. Do not regenerate these
 * from an LLM — they are the ground truth the LLM is being
 * calibrated against. Every `cveId`/`ghsaId` was verified against
 * the OSV database.
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
      // The vulnerable code is the template literal that builds the
      // regex source string (e.g. `(\\s*)${src[t.LONETILDE]}\\s+` in
      // node-semver internal/re.js). The compiled `RegExp` itself
      // isn't directly visible in the AST since it's built at module
      // load via `new RegExp(value)`. A2's matcher fires on the
      // template_string node; A3 calibration confirms this matches
      // the upstream vulnerable lines.
      kind: "template_string",
      constraints: [
        "template literal whose source contains an unbounded whitespace class (`\\\\s*` or `\\\\s+`)",
        "the unbounded class is adjacent to a `${}` interpolation slot",
        "the resulting string is consumed as a regex source (passed to `new RegExp`, `re[i] = new RegExp(value)`, or assigned to a regex token map)",
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
      // The bug shape in upstream follow-redirects (line 464 of the
      // vulnerable commit) is a regex *literal* used to filter
      // headers: `removeMatchingHeaders(/^(?:authorization|cookie)$/i, …)`.
      // The fix added `proxy-authorization` to the alternation. Other
      // implementations of the same bug class might use an array or
      // object allowlist instead — those are A2.x territory; A1 seed
      // pins the upstream-canonical shape for A3 calibration.
      kind: "regex",
      constraints: [
        "regex literal whose pattern is an alternation of HTTP header names (e.g. `^(?:authorization|cookie)$`)",
        "alternation contains `authorization` and/or `cookie` (case-insensitive flag `/i`)",
        "alternation omits `proxy-authorization`",
        "the regex is consumed by a redirect-handler code path (function or method whose name contains `redirect`)",
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
  {
    cveId: "CVE-2019-10744",
    ghsaId: "GHSA-jf85-cpcp-j695",
    bugClass: "prototype-pollution-recursive-merge",
    cwe: "CWE-1321",
    languages: ["javascript", "typescript"],
    astShape: {
      // The vulnerable code in lodash's CVE-2019-10744 fix commit
      // (a01e4fa, lodash.js ~6589) is the `safeGet` helper — a
      // `function_declaration`. The recursive `defaultsDeep` /
      // `baseMerge` path reads every source key through this guard;
      // the fix added a `constructor` check alongside the existing
      // `__proto__` one. A2's matcher fires on the function node;
      // the key-guard omission is the discriminating constraint.
      kind: "function_declaration",
      constraints: [
        "function is a key-access helper used by a recursive merge/clone path (name contains `get`, `merge`, `set`, or `assign`)",
        "function body guards the `__proto__` key (early-returns or skips when `key === '__proto__'`)",
        "function body does NOT guard the `constructor` key — a `{ constructor: { prototype: {...} } }` payload walks through unfiltered",
      ],
    },
    dataFlow: {
      source:
        "attacker-controlled `source` object passed to `_.defaultsDeep` / `_.merge` (e.g. a parsed JSON request body)",
      sink: "`Object.prototype` — a property assigned onto the global object prototype, polluting every object in the process",
      propagation:
        "the recursive merge walks the source's `constructor` → `prototype` keys; because the key-access guard only rejects `__proto__`, the walk descends into and writes onto the prototype chain",
    },
    summary:
      "lodash's `defaultsDeep` (and the shared `baseMerge` path) recursively copies source keys through a `safeGet` helper that rejected `__proto__` but not `constructor`; a crafted `{ constructor: { prototype: {...} } }` source pollutes `Object.prototype`, letting an attacker add or override properties on every object in the program.",
  },
  {
    cveId: "CVE-2021-21315",
    ghsaId: "GHSA-2m8v-572m-ff2v",
    bugClass: "os-command-injection-shell-exec",
    cwe: "CWE-78",
    languages: ["javascript", "typescript"],
    astShape: {
      // The sink for CVE-2021-21315 (systeminformation, fix commit
      // 07daa05) is the `child_process.exec`/`execSync` call that runs
      // a command line built from a caller-supplied parameter
      // (`host`/`proc`/`srv`). The fix added strict `typeof === 'string'`
      // checks so an attacker can't pass an array that slips past the
      // per-character shell sanitizer. A2's matcher fires on the
      // `call_expression` that invokes the shell exec.
      kind: "call_expression",
      constraints: [
        "callee resolves to `child_process.exec` / `execSync` (or a bare `exec` imported from `child_process`)",
        "first argument is a command-line string built by `+` concatenation or a template literal from a function parameter",
        "the interpolated parameter is not constrained to a string before it reaches the call (no `typeof param === 'string'` guard, no argv-array form like `execFile(cmd, [args])`)",
      ],
    },
    dataFlow: {
      source:
        "caller-supplied `host` / `proc` / `srv` argument (a value an attacker can pass as an array to bypass the string sanitizer)",
      sink: "`exec(commandLine)` — a shell command line passed to `/bin/sh -c`",
      propagation:
        "the parameter is concatenated into a `ping`/`ps` command string; because non-string input is never rejected, an array argument evades the per-character `sanitizeShellString` scan and shell metacharacters survive into the spawned shell",
    },
    summary:
      "systeminformation builds OS command lines (`ping`, `ps`, service queries) by concatenating caller-supplied parameters and runs them through `child_process.exec`; the parameter was sanitized per-character but never required to be a string, so passing an array bypassed the sanitizer and let an attacker inject arbitrary shell commands.",
  },
  {
    cveId: "CVE-2018-1002204",
    ghsaId: "GHSA-3v6h-hqm4-2rg6",
    bugClass: "path-traversal-archive-extraction",
    cwe: "CWE-22",
    languages: ["javascript", "typescript"],
    astShape: {
      // The vulnerable code for CVE-2018-1002204 (adm-zip "Zip-Slip",
      // fix commit 62f6400) is the `pth.resolve(targetPath, entryName)`
      // call that computes an extraction target from an archive-
      // controlled entry name. The fix added a
      // `target.startsWith(targetPath)` containment check; the seed
      // pins the unchecked `call_expression` itself.
      kind: "call_expression",
      constraints: [
        "callee resolves to `path.resolve` / `path.join` (member expression `path.resolve` or named import)",
        "one argument is an archive/upload entry name (`entry.entryName`, `entryName`, `zipEntry.name` — a value the attacker controls)",
        "the resolved path is passed to a filesystem write/mkdir (`fs.writeFileSync`, `fs.createWriteStream`, `makeDir`) without a containment check that the result `startsWith` the extraction root",
      ],
    },
    dataFlow: {
      source:
        "the `entryName` field of an entry inside an attacker-supplied zip/tar archive (may contain `../` traversal segments)",
      sink: "`fs.writeFileSync(target, ...)` / `fs.createWriteStream(target)` where `target` resolves outside the intended extraction directory",
      propagation:
        "`path.resolve(targetPath, entryName)` collapses the `../` segments and yields a path above `targetPath`; with no `startsWith(targetPath)` guard the write lands at the attacker-chosen location",
    },
    summary:
      "adm-zip's archive-extraction routines build each output path with `path.resolve(targetPath, entryName)` from the archive's own entry names and write to it without verifying the result stays inside the extraction directory; a zip entry named `../../foo` (the \"Zip-Slip\" pattern) lets an attacker create or overwrite files anywhere the process can write.",
  },
  {
    cveId: "CVE-2020-28168",
    ghsaId: "GHSA-4w2v-q235-vp99",
    bugClass: "ssrf-redirect-proxy-bypass",
    cwe: "CWE-918",
    languages: ["javascript", "typescript"],
    astShape: {
      // The vulnerable code for CVE-2020-28168 (axios, fix commit
      // 8a90bcf) is the `transport.request(options, ...)` call that
      // issues an outbound HTTP request: the proxy/destination is
      // applied to the FIRST request only, and the call site has no
      // `options.beforeRedirect` re-validation hook. The fix inserted
      // a `beforeRedirect` handler that re-pins the proxy on every
      // hop. A2's matcher fires on the `call_expression` that issues
      // the request.
      kind: "call_expression",
      constraints: [
        "callee is an HTTP request issuer (`http.request` / `https.request` / `transport.request` / `request(...)`)",
        "the request `options` object is built from a caller-supplied URL or proxy config (`config.url`, `parsed.hostname`, `proxy.host`)",
        "no per-redirect re-validation is wired before the call — no `options.beforeRedirect` handler and no allowlist check applied to the redirected hop",
      ],
    },
    dataFlow: {
      source:
        "a caller-supplied request URL pointing at an attacker-controlled server that answers with a 3xx redirect",
      sink: "`transport.request(options, ...)` — the follow-up request issued directly to the redirect's `Location`, reaching a restricted internal host or IP",
      propagation:
        "proxy host/port are written into `options` for the initial request only; the redirect-follow logic reuses the underlying transport without re-applying the proxy, so the redirected request escapes the proxy boundary and hits internal infrastructure",
    },
    summary:
      "axios applies proxy settings to the initial outbound request but not to requests issued while following an HTTP redirect; a server the caller is pointed at can answer with a redirect to an internal host or IP, and axios connects to it directly, bypassing the proxy and enabling server-side request forgery against the application's internal network.",
  },
  {
    cveId: "CVE-2019-10752",
    ghsaId: "GHSA-m9jw-237r-gvfv",
    bugClass: "sql-injection-json-path-interpolation",
    cwe: "CWE-89",
    languages: ["javascript", "typescript"],
    astShape: {
      // The vulnerable code for CVE-2019-10752 (sequelize, fix commit
      // 9bd0bc1) is the template literal that builds a SQL fragment by
      // interpolating an attacker-supplied JSON sub-path
      // (`path.join('.')`) directly into the query string with no
      // identifier escaping. The fix routed paths through an escaping
      // `jsonPathExtractionQuery` helper. Like CVE-2022-25883, the
      // matchable node is the `template_string` that assembles the SQL
      // text — the compiled query is built at call time.
      kind: "template_string",
      constraints: [
        "template literal whose text is a fragment of SQL (contains an operator/path syntax such as `->>`, `json_extract`, `WHERE`, or a quoted `'$'` JSON-path marker)",
        "a `${}` interpolation slot carries a caller-derived path/column value (e.g. `path.join('.')`, `smth.path`, a split user string)",
        "the interpolated value is NOT passed through an identifier-quoting / escaping helper (`escape`, `quoteIdentifier`, `addTicks`) before landing in the template",
      ],
    },
    dataFlow: {
      source:
        "a JSON sub-path string passed by the caller to `sequelize.json(path)` (often built from a request field)",
      sink: "the SQL query string sent to the database driver, into which the path segments were interpolated verbatim",
      propagation:
        "`smth.path` is split on `.` and the segments are joined back into a template literal that becomes part of a `json_extract` / `->>` clause; with no escaping a segment containing `')) ... --` breaks out of the JSON-path literal and injects SQL",
    },
    summary:
      "sequelize's `sequelize.json()` helper builds MySQL/MariaDB/SQLite JSON-path queries by interpolating the caller-supplied sub-path into the SQL string through a template literal without escaping the path segments as identifiers; a crafted path closes the quoted JSON-path literal and appends arbitrary SQL, yielding SQL injection.",
  },
  {
    cveId: "CVE-2022-39353",
    ghsaId: "GHSA-crh6-fp67-6883",
    bugClass: "xxe-malformed-xml-trusted-dom",
    cwe: "CWE-611",
    languages: ["javascript", "typescript"],
    astShape: {
      // CVE-2022-39353 (@xmldom/xmldom, fix commit 7ff7c10) is a
      // parser-internal bug: xmldom accepted not-well-formed XML
      // (multiple top-level elements) and attached every root to the
      // Document instead of rejecting it. The exploitable surface in
      // *caller* code is the `parser.parseFromString(xml, ...)` call
      // that parses untrusted XML and whose resulting DOM is then
      // trusted (searched whole-document, `documentElement` read)
      // without rejecting a multi-root document. A2's matcher fires
      // on that `call_expression`.
      kind: "call_expression",
      constraints: [
        "callee resolves to an XML parser entry point (`DOMParser().parseFromString`, `parseFromString`, `parseXml`, `parseXmlString`)",
        "the parsed input is attacker-controlled XML (a request body, uploaded file, or signed-XML/SAML blob)",
        "the resulting document is consumed structurally (`getElementsByTagName`, `documentElement`, child iteration) with no check that the document is well-formed / has a single root, and no parser hardening (`onError`/throwing config, single-root assertion)",
      ],
    },
    dataFlow: {
      source: "an attacker-supplied XML document parsed with `DOMParser.parseFromString`",
      sink: "DOM-tree consumers (`getElementsByTagName`, `documentElement`) that assume a single, well-formed root element",
      propagation:
        "xmldom silently appends every top-level element of a multi-root document to `Document.childNodes`; a consumer that searches the whole document or reads `documentElement` can be steered to a smuggled extra root, bypassing signature/structure checks",
    },
    summary:
      "@xmldom/xmldom's DOMParser parsed XML that is not well-formed — notably documents with multiple top-level elements — and attached every root node to the Document without throwing; dependents that parse untrusted XML and then trust the DOM shape (whole-document searches, `documentElement`) can be fed a smuggled extra root, an XML-external-entity-class (CWE-611) input-validation flaw with security impact on signed-XML/SAML consumers.",
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
 * All seed patterns. The first 5 entries are the Tier-1 calibration
 * seeds (Tier-2 seeds are appended after them) so the test assertions
 * in root-cause.test.ts stay diff-stable when new Tier-2 seeds are
 * added.
 */
export const SEED_PATTERNS: readonly RootCausePattern[] = SEEDS;

/** Set of canonicalized ids that have a seed (CVE and GHSA both included). */
export const SEEDED_IDS: ReadonlySet<string> = new Set(BY_ID.keys());
