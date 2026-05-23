# Consumer-hunt triage log

**Started:** 2026-05-23
**Companion to:**
- [`2026-05-23-differential-fuzz-first-run.md`](./2026-05-23-differential-fuzz-first-run.md)
- [`2026-05-23-consumer-hunt-candidates.md`](./2026-05-23-consumer-hunt-candidates.md)

PoC harness:
[`benchmarks/differential-fuzz/poc-harness.ts`](../../benchmarks/differential-fuzz/poc-harness.ts).
Six confirmed-bypass inputs; verdicts are PASS / BYPASS / ERROR / INFO.

## Pre-commitments

- **Kill date:** 2026-06-02 (10 days from start). If no exploitable
  candidate by then, write up the negative result and stop.
- **Scope:** SSRF-class only. XSS-via-scheme tab-bypass (`sanitize-html`,
  etc.) is a separate hunt with a different harness.
- **Disclosure:** any finding → private GitHub security advisory first,
  never a public issue. Wait for maintainer or offer patch. CVE via the
  advisory flow.

## Log

| Date | Pkg @ ver | Validator | Fetcher | Bypasses | Verdict | Notes |
|---|---|---|---|---:|---|---|
|  | _start filling in as you check each candidate_ | | | | | |

### Column definitions

- **Pkg @ ver** — `name@semver` of the version you tested. Pin the exact
  version so the row is reproducible.
- **Validator** — the function in the package responsible for blocking.
  Path within the package source, e.g. `src/validate.js:isAllowed`.
- **Fetcher** — what actually makes the network request after validation.
  Same notation. "n/a" if the package only validates and the caller fetches.
- **Bypasses** — count from the harness output: `N / 6`.
- **Verdict** — one of: `hardened` (0 bypasses), `partial`
  (1-2 bypasses, narrow surface), `exploitable` (3+ bypasses, broad
  surface), `inconclusive` (couldn't model the boundary cleanly).
- **Notes** — anything noteworthy: hardening already in place, edge
  conditions, links to relevant lines of source, disclosure status.

## Workflow per candidate

1. `npm install <pkg>` in a scratch directory; pin to latest published.
2. Read the README; identify the validator export.
3. Write a 10-line `poc-<pkg>.mjs` that wires the validator into
   `runPocHarness`.
4. Run it. Capture the bypass count.
5. **If 0 bypasses:** add row, move on. Don't burn time hunting variants.
6. **If ≥1 bypass:** trace the validator's source to confirm the exact
   anti-pattern. Check if there's an open issue or unmerged PR addressing
   it (someone may have noticed but the fix didn't land).
7. **If exploitable on current main:** stop, escalate to the disclosure
   flow in `2026-05-23-consumer-hunt-candidates.md` § "Don't disclose
   blindly". Do not publish or commit a PoC against a real consumer
   until disclosure resolves.

## Findings

_(populate as the hunt yields results)_

## End-of-hunt summary

_(fill in on the kill date or when a CVE is filed, whichever first)_
