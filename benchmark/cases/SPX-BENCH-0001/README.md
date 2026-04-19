# SPX-BENCH-0001 — JWT in localStorage (CWE-922)

## What this tests

mythos-agent's `JwtScanner` should flag any `localStorage.setItem(...)`
or `sessionStorage.setItem(...)` call that looks like it is persisting
a JWT — either by key (`jwt`, `token`, `auth_token`, `access_token`)
or by value heuristic.

## Why it matters

JWTs are bearer tokens: anyone who holds the raw value is the user.
`window.localStorage` is readable by any script running in the
document, so any XSS — whether direct, via a third-party script, or
via a compromised browser extension with the right host permission —
walks away with the user's session. Cookie-based storage with
`HttpOnly` and `SameSite=Strict` closes this class.

## Files

- `vulnerable/auth.ts` — the anti-pattern the scanner must detect.
- `safe/auth.ts` — the intended remediation (in-memory + HttpOnly
  refresh cookie on the server side).
- `case.yml` — metadata + the single expected finding (the scanner
  must emit at least one result whose `rule` contains the
  `jwt-stored-localstorage` class against `vulnerable/auth.ts`).

## Lineage

This is the first case in the Sphinx Benchmark corpus. The full
corpus target (Q4 2026) is 500 cases across CWE Top 25 + OWASP Top
10 + the AI-misuse class. See `docs/benchmark.md` for the schema,
scoring rules, and contribution workflow.
