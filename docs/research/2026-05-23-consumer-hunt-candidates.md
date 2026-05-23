# Consumer hunt — candidates for the SSRF-bypass primitive

**Date:** 2026-05-23
**Companion to:** [`2026-05-23-differential-fuzz-first-run.md`](./2026-05-23-differential-fuzz-first-run.md)

The fuzzer proved the validate-vs-fetch SSRF-bypass primitive is real in
stock Node 22. To turn it into a CVE we need to find an *unpatched* OSS
package that exhibits the exact anti-pattern:

```js
// Validation step uses legacy parser
const host = require('url').parse(input).hostname;
if (BLOCKLIST.includes(host)) throw new Error('blocked');

// Request step uses WHATWG (fetch, axios with native URL, http.request with URL object)
await fetch(input);   // canonicalizes 0x7f000001 → 127.0.0.1 at DNS time
```

This file scopes the hunt. **It does not start it** — that's the next session.

## Search strategy

### Primary: grep.app / GitHub code search

Two queries that surface the anti-pattern directly:

```
# Files that use both url.parse and fetch:
language:javascript /url\.parse\(/ AND /\bfetch\(/

# Files that use both url.parse and http.request/get:
language:javascript /url\.parse\(/ AND /https?\.(get|request)\(/

# Specific hostname checks against literal '127.0.0.1' or 'localhost':
language:javascript /url\.parse.*hostname.*(127\.0\.0\.1|localhost|169\.254)/
```

Add `path:**/package.json` filter or stars:>100 to drop hobby projects.

### Secondary: NPM dependents of `url-parse` and `parseurl`

`url-parse` has 50M+ weekly downloads — the dependents graph is rich. Filter
to packages whose stated purpose involves URL validation or routing:
proxies, link previews, webhook senders, OAuth.

```
npm view url-parse dependents | grep -iE 'proxy|webhook|preview|fetch|validate|allowlist'
```

## Categories (highest → lowest a priori probability)

### 1. Webhook / outbound HTTP libraries
- `octokit/webhooks.js` (delivery) — does it validate target URLs?
- `slack/webhook` — same question
- `stripe/stripe-node` for outbound endpoints
- `request-promise`, `got`, `axios` — these are the *fetchers*; usually OK,
  but their built-in URL handling has historically been buggy
- Generic webhook-relay services on NPM (search `webhook+relay`)

### 2. Link-preview / OG-card / unfurl services
These fetch arbitrary user-supplied URLs and parse OG tags. Pattern:
SSRF-validate input host, then fetch. Many.
- `open-graph-scraper`
- `metascraper` family
- `link-preview-js`
- `node-html-link-preview`
- Any self-hosted Mattermost/Rocket.Chat unfurl path

### 3. Image / file proxies
SSRF-relevant because they typically validate against private-network ranges.
- `imageproxy`, `imgproxy-node` wrappers
- avatar-proxy libraries

### 4. OAuth / OpenID callback validators
Validators check `redirect_uri` matches a registered allowlist. If the
allowlist comparator uses one parser and the eventual 302 / form-post uses
another, that's an open-redirect.
- `passport` strategies (especially custom ones)
- `node-openid-client` — historically careful, but worth checking
- Smaller OAuth gateway libs

### 5. SSRF allowlist / denylist libraries (the canonical targets)
- `ssrf-req-filter`
- `request-filtering-agent` (Sindre Sorhus — likely already careful, but
  exact behavior on `0x7f000001` is worth verifying)
- `ssrfcheck`
- Anything else from the `ssrf` keyword on NPM

### 6. Markdown / link-sanitization
Markdown→HTML renderers that strip "dangerous" URLs (`javascript:`, etc.).
The same scheme-bypass tricks (tab/CR/LF in scheme) hit here. Different
exploit class (XSS rather than SSRF) but same primitive.
- `dompurify` (probably hardened)
- `sanitize-html`
- Markdown plugins for redirect URLs in MD-it / remark

## Triage rubric per candidate

For each candidate package:

1. **Find the validator.** Grep for `url.parse`, `parseURL`, `URL(`,
   `new URL`. Note which one is used and whether `.hostname` is the
   comparison key.
2. **Find the fetcher.** Grep for `fetch(`, `axios`, `got`, `http.get`,
   `http.request`. Note whether it receives the original string or the
   parsed object.
3. **Mismatch?** If validator uses `url.parse` and fetcher passes the
   original string → potential exploit. Reproduce with the 6 PoC inputs
   from the research doc.
4. **Already patched?** Check Snyk / GitHub advisories for the package.
   `npm audit` against a pinned `package.json` at the latest version.
5. **Real consumers?** If exploitable, find a major user (an
   end-user-facing app, not a wrapper). Patch path:
   maintainer-disclosure → fix → CVE.

## Out of scope (for this hunt — useful later)

- **Markdown XSS via control-char schemes.** Same fuzzer pattern, different
  parsers (DOMPurify, sanitize-html, marked). Would be a separate run with
  a Markdown-targeted corpus.
- **DNS rebinding.** Beyond differential parsing — needs a TOCTOU lookup
  primitive (validator resolves once, fetcher resolves again moments
  later). Outside the URL-parser scope.
- **Idna/punycode edge cases (`xn--`).** The fuzzer surfaced fullwidth
  homoglyphs but didn't push raw punycode. Worth a focused secondary corpus.

## Estimate

A motivated hunter probably needs 3–10 days of focused work to find one
exploitable consumer, write a PoC, disclose, and shepherd a fix. Estimate
heavily depends on whether the obvious targets (link-preview libs) are
already hardened — if they are, this gets longer. If they aren't, it's
much shorter.

## Don't disclose blindly

When (if) a finding lands:

1. Confirm with PoC against current `main` of the target.
2. Open a private security advisory on GitHub (not a public issue).
3. Wait for the maintainer; offer a patch if they're slow.
4. Get a CVE assigned.
5. Publish the writeup pointing back to this directory.

The fuzzer's role ends at step 1 — everything after is human work.
