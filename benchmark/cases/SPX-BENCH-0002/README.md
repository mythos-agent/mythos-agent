# SPX-BENCH-0002 — Mass-assignment role escalation

**CWE**: CWE-269 (Improper Privilege Management)
**Severity**: critical
**Languages**: TypeScript, JavaScript
**Classes**: authorization, mass-assignment, privilege-escalation

## The bug

The `POST /users/:id` handler copies `req.body.role` into the database
update payload. An authenticated but low-privileged attacker posts
`{"role": "admin"}` along with a legitimate profile field update and
is granted admin privileges on the next write.

See [`vulnerable/user.ts`](vulnerable/user.ts).

## The fix

1. **Allowlist** the client-editable fields rather than spreading
   `req.body`. The safe fixture builds an explicit `patch` object
   that only names `name` and `email`.
2. **Separate endpoint** for privilege changes. A real system pairs
   the allowlist with a dedicated `/admin/users/:id/role` handler
   that requires admin auth and server-side actor-identity checks
   (not shown in the safe fixture).

See [`safe/user.ts`](safe/user.ts).

## What the scanner catches

`business-logic-scanner` rule `biz-role-escalation` matches the
direct `req.body.role` usage in the update payload. The rule also
covers `isAdmin`, `permission`, and `privilege` keys with the same
anti-pattern. Patterns are regex-based; the scanner does not need
the file to run.

## Sources

- <https://cwe.mitre.org/data/definitions/269.html>
- <https://owasp.org/www-community/attacks/Mass_Assignment>
- OWASP API Security Top 10 — Broken Object Property Level Authorization
