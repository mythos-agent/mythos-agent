# SPX-BENCH-0003 — Session cookie missing HttpOnly and Secure

**CWE**: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
**Related**: CWE-1004 (Sensitive Cookie Without HttpOnly)
**Severity**: high
**Languages**: TypeScript, JavaScript
**Classes**: session-management, cookie-flags, xss-token-theft, csrf

## The bug

The express-session middleware is configured without `httpOnly: true`
or `secure: true` on its cookie object. The session cookie is
readable from JavaScript (so an XSS anywhere on the origin exfiltrates
it) and is transmitted over cleartext HTTP whenever the user lands on
a non-TLS page.

See [`vulnerable/session.ts`](vulnerable/session.ts).

## The fix

Set both flags, plus `sameSite: "strict"` (or `"lax"` if you have
cross-site workflows that require it) for CSRF defense:

```ts
cookie: {
  maxAge: 60 * 60 * 1000,
  httpOnly: true,
  secure: true,
  sameSite: "strict",
}
```

The safe fixture shows the full remediation.

## What the scanner catches

`session-scanner` rule `session-insecure-cookie` fires on any
`cookie: { ... }` block that does not contain `httpOnly: true`
within 200 characters of the opening brace — and separately on the
same pattern for `secure: true`. So the vulnerable fixture produces
two overlapping findings (one per missing flag); the safe fixture
produces neither because both flags appear within the cookie block.

## Sources

- <https://cwe.mitre.org/data/definitions/614.html>
- <https://cwe.mitre.org/data/definitions/1004.html>
- <https://owasp.org/www-community/HttpOnly>
