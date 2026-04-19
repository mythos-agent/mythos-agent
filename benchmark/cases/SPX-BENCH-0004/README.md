# SPX-BENCH-0004 — CSP with unsafe-inline and unsafe-eval

**CWE**: CWE-693 (Protection Mechanism Failure)
**Severity**: high
**Languages**: TypeScript, JavaScript
**Classes**: headers, csp, xss-mitigation-failure

## The bug

The server emits a Content-Security-Policy header that includes
`'unsafe-inline'` and `'unsafe-eval'` in `script-src`. Both keywords
re-enable the XSS execution paths CSP was supposed to block:

- **`'unsafe-inline'`** re-allows inline `<script>` elements and
  inline event handlers (`onclick=`, `onload=`, …), the classic
  reflected-XSS payload shape.
- **`'unsafe-eval'`** re-allows `eval()`, `new Function(...)`, and
  the string form of `setTimeout`/`setInterval`.

A CSP that permits these is in some ways worse than no CSP: compliance
scanners and security reviews may treat the header's mere presence as
"we have CSP" without checking the directive values, producing false
confidence.

See [`vulnerable/app.ts`](vulnerable/app.ts).

## The fix

Strict `script-src 'self'` (and `style-src 'self'`). Where a
genuine use of inline script is necessary, attach a per-response
nonce to both `script-src 'nonce-X'` and the `<script nonce="X">`
element.

See [`safe/app.ts`](safe/app.ts).

## What the scanner catches

`headers-scanner` rule `header-csp-unsafe` fires on any line that
contains both `Content-Security-Policy` and one of `unsafe-inline`
or `unsafe-eval`. It's a misconfiguration rule (fires on presence
of the bad pattern) rather than a missing-header rule (which fires
on whole-project absence), so it's robust to the scaffold scanning
the whole case directory: the rule matches only on lines inside
`vulnerable/app.ts`, not `safe/app.ts`.

## Sources

- <https://cwe.mitre.org/data/definitions/693.html>
- <https://owasp.org/www-project-secure-headers/>
- <https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP>
