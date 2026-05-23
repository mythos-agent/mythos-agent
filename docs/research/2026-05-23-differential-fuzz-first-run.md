# Differential URL-parser fuzzer — first run

**Date:** 2026-05-23
**Tool:** `src/dast/differential-fuzzer` (shipped in PR #93)
**Run config:** `--count 2000 --seed 1`, deterministic; report at
`benchmarks/differential-fuzz/results/2026-05-23T04-36-57-450Z/`.

## Headline

2000 fuzzed URL inputs → **1046 divergence classes** (52% of inputs disagree on
at least one parsed field across native `URL`, `url-parse`, and legacy
`url.parse`). LLM triage (Sonnet 4.6) categorized **724 likely-exploitable**,
321 spec-ambiguity, 1 unparseable.

The most security-relevant cluster — **86 classes covering IP-address
canonicalization** — reproduces the canonical SSRF-filter-bypass primitive
in stock Node 22, without any external library:

```js
const legacy = require('url').parse('http://0x7f000001/').hostname;
//   => '0x7f000001'
const whatwg = new URL('http://0x7f000001/').hostname;
//   => '127.0.0.1'
```

Any Node application that validates URLs with `url.parse()` (against a denylist
like `['127.0.0.1','localhost','169.254.169.254']`) and then fetches via
`fetch()` or `http.get()` is potentially exploitable.

## What the fuzzer actually does

`runDifferentialFuzz` (see `src/dast/differential-fuzzer/index.ts`):

1. Expands a hand-curated **42-seed corpus** of URL-confusion patterns
   (8 families: embedded-@, backslash, missing-slash, whitespace, unicode-IDN,
   control-char, userinfo-port, ip-oddity) into `count` inputs via a
   deterministic mulberry32-seeded mutator that applies 1–3 random ops
   per input (insert / duplicate / delete / flip-case / append) drawn from a
   confusion-character pool.
2. Parses each input across three adapters — `native-url` (WHATWG),
   `url-parse`, legacy `url.parse` — under worker-thread isolation with a
   per-call timeout (a hang is a recorded `hang: true` result, not a crashed
   benchmark).
3. **Compares pairwise** on six security-critical fields (protocol, hostname,
   port, pathname, username, password) and classifies divergences with a
   **skeleton-based signature** (letters→`a`/`A`, digits→`0`) that groups
   `http://evil1.com/` and `http://evil9.com/` into a single class.
4. Asks an LLM to label each class as `spec-ambiguity` / `likely-exploitable`
   / `dos` with a one-sentence rationale.

## Themes in the 724 likely-exploitable bucket

| Theme | Classes | Hits | Representative input |
|---|---:|---:|---|
| IP-canon (hex `0x7f...`) | 30 | 65 | `http://0x7f000001/` |
| IP-canon (octal `0177.0.0.1`) | 27 | 53 | `http://0177.0.0.1/` |
| IP-canon (dotless decimal) | 12 | 29 | `http://2130706433/` |
| IP-canon (shorthand `127.1`) | 5 | 21 | `http://127.1/` |
| IPv6-mapped loopback | 12 | 34 | `http://[::ffff:127.0.0.1]/` |
| IDN / fullwidth | 173 | 364 | `http://ｅｖｉｌ.com/`, `http://evil。com/` |
| Tab/CR/LF in scheme | 38 | 79 | `"ht\ttp://evil.com/"` |
| Triple-slash authority | 71 | 130 | `http:///evil.com/` |
| Single-slash scheme | 115 | 333 | `http:/evil.com/` |
| Userinfo `@` confusion | 51 | 70 | `http://good.com@evil.com/` |
| Backslash | 146 | 295 | `http:\\evil.com` |

The five IP-canonicalization rows together (86 classes, 202 hits) are the
strongest single signal because the underlying behavior is reproducible in
six lines of stock Node:

```text
input "http://0x7f000001/"          legacy="0x7f000001"        whatwg="127.0.0.1"
input "http://2130706433/"          legacy="2130706433"        whatwg="127.0.0.1"
input "http://0177.0.0.1/"          legacy="0177.0.0.1"        whatwg="127.0.0.1"
input "http://127.1/"               legacy="127.1"             whatwg="127.0.0.1"
input "http://[::ffff:127.0.0.1]/"  legacy="::ffff:127.0.0.1"  whatwg="[::ffff:7f00:1]"
```

`legacy` is `require('url').parse(input).hostname`; `whatwg` is
`new URL(input).hostname`.

## What this is and isn't

**Is:** a clean reproduction of a well-known primitive — WHATWG canonicalizes
IPv4/IPv6 hostnames, legacy `url.parse` returns the literal string. Anyone who
writes `if (BLOCKLIST.includes(url.parse(input).hostname)) reject()` and then
fetches the original `input` ships an SSRF bug.

**Isn't (yet):** a CVE. The primitive doesn't become a 0-day until an
unpatched OSS package is shown to use this exact validate-vs-fetch pattern.
That hunt is the natural follow-up and lives outside this fuzzer.

## Other clusters worth a closer look

- **Tab/CR/LF in scheme** (38 classes): WHATWG strips C0 controls per spec
  while legacy `url.parse` does not. `fetch('ht\ttp://evil.com/')` resolves;
  `url.parse('ht\ttp://evil.com/').protocol` is empty. Same pattern, different
  primitive.
- **`http://[::ffff:127.0.0.1]/`** (12 classes): WHATWG renders the
  mapped-IPv4 portion in hex (`[::ffff:7f00:1]`), legacy returns the
  human form. A blocklist on `127.0.0.1` substring misses both.
- **IDN fullwidth `ｅｖｉｌ.com` / `evil。com`** (173 classes): Punycode/IDNA
  normalization is parser-dependent. Allowlist of literal `evil.com` may or
  may not match depending on which parser produced the comparator.
- **`http:///evil.com/`** triple-slash and **`http:/evil.com/`** single-slash
  (186 combined classes): WHATWG vs legacy disagree on whether the empty
  authority is a hostname, a path segment, or a malformed input. Allowlist
  parsers that see empty authority + path may accept and route to a different
  destination than the eventual HTTP client.

## Knobs the fuzzer surfaces but this run didn't exercise

- **Real-target lookup** — the fuzzer doesn't currently feed the divergent
  hostnames into a network sink. A v2 could `dns.lookup` each side to verify
  the canonicalization difference actually points at different IPs.
- **Custom parser sets** — only three adapters are wired. Adding `whatwg-url`,
  `parse-url`, or `tldts`/`psl` would surface additional pairwise differences,
  especially around subdomain extraction (relevant to SameSite cookie scope
  bypasses).
- **Larger corpora** — at `--count 2000` the seed bias dominates; the
  mutation walk hasn't reached deep enough into structural mutations. A
  `--count 20000` run would surface lower-frequency classes (the long tail
  in the "other" bucket).

## How to reproduce

```powershell
# Set environment (PowerShell):
$env:NODE_USE_ENV_PROXY = 1                  # if your network needs a proxy
$env:HTTPS_PROXY        = "http://127.0.0.1:10808"
$env:HTTP_PROXY         = "http://127.0.0.1:10808"
$env:ANTHROPIC_API_KEY  = "sk-ant-..."

# Run:
npm run benchmark:differential-fuzz -- --count 2000 --seed 1

# Re-triage an existing report without redoing the fuzz:
node dist-benchmarks/benchmarks/differential-fuzz/retriage.js `
  benchmarks/differential-fuzz/results/<subdir>/report.json
```

The seed is the only stochastic input; identical seed + count yields an
identical corpus and identical divergence classes. The LLM categorization
is the one non-deterministic step (single-shot per class, no self-consistency).

## Next steps

1. **Consumer hunt.** Search NPM + GitHub for packages that combine
   `url.parse(...).hostname` validation with `fetch(...)` or `http.get(...)`
   routing of the original input. Candidate categories: SSRF allowlist libs,
   webhook delivery, OAuth-callback validators, redirect followers,
   image/avatar proxies. Filed as task #41.
2. **v2 of this fuzzer.** Add `dns.lookup` cross-check on the divergent
   hostnames (so an SSRF-class label is grounded in a real address
   disagreement, not parser opinion). Add more parsers. Default `--count` up.
3. **Reuse the methodology.** The same harness — corpus + mutator + N
   adapters + skeleton-dedup + LLM triage — should port to JSON and Markdown
   parsers, where the bug class is "renderer A sees a link, renderer B sees
   text" (Markdown XSS) or "validator A accepts, runtime B rejects/silently
   coerces" (JSON config injection).
