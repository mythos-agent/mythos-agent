# SPX-BENCH-0005 — Hardcoded AWS access key

**CWE**: CWE-798 (Use of Hard-coded Credentials)
**Severity**: critical
**Languages**: TypeScript, JavaScript
**Classes**: secrets, hardcoded-credentials, supply-chain-risk

## The bug

An AWS access key is hardcoded as a string literal. Once the commit
lands, the key is in git history permanently — mirrors, forks, and
package tarballs that have already pulled the commit retain it even
after a delete-and-force-push. Any contributor, any CI runner, any
package-lookup tool that can read the repo has it.

See [`vulnerable/config.ts`](vulnerable/config.ts).

## The fix

Read credentials from the environment at startup; fail loudly on
absence rather than falling back to a hardcoded literal. A production
system layers AWS Secrets Manager, SOPS-encrypted config, or HashiCorp
Vault on top. The safe fixture shows the baseline:

```ts
accessKeyId: requiredEnv("AWS_ACCESS_KEY_ID"),
```

See [`safe/config.ts`](safe/config.ts).

If a key has already been committed, rotating it in AWS IAM is
step zero — `git filter-branch` only cleans your copy of history,
not the copies downstream consumers already have.

## What the scanner catches

`secrets-scanner` rule `aws-access-key` fires on the pattern
`(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])` — the
well-known AWS-docs canonical access key shape. The pattern uses
negative-lookbehind/lookahead on alphanumeric characters so it
matches standalone tokens and not substrings of longer random
strings.

Rounds out the v0.1 scaffold's scanner coverage — all 5 wired
scanners (Secrets, JWT, Headers, Session, BusinessLogic) now have
at least one benchmark case exercising them.

## Sources

- <https://cwe.mitre.org/data/definitions/798.html>
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html>
- AWS-documented placeholder: `AKIAIOSFODNN7EXAMPLE` (from AWS SDK
  examples; intentionally-invalid format used in docs)
