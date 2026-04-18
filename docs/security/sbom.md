# SBOM Policy

How mythos-agent produces, distributes, and maintains its Software Bill of Materials.

## What we publish

For every release of mythos-agent, we publish a CycloneDX SBOM in two formats:

| Artifact | Format | Spec version |
|---|---|---|
| `mythos-agent-sbom.cdx.json` | CycloneDX JSON | 1.6 |
| `mythos-agent-sbom.cdx.xml` | CycloneDX XML | 1.6 |

Both are attached to the corresponding GitHub release and are signed with cosign (keyless). Signatures (`.sig`) and certificates (`.crt`) are attached alongside.

The SBOM is also retained as a CI artifact for one year, enabling reconstruction even if the release page is altered.

## How we generate it

Generation is automated by [`.github/workflows/sbom.yml`](../../.github/workflows/sbom.yml). The pipeline:

1. Checks out the release tag
2. Installs production dependencies only (`npm ci --omit=dev`)
3. Runs `@cyclonedx/cyclonedx-npm` to produce both JSON and XML
4. Validates the SBOM against the CycloneDX 1.6 schema
5. Signs each SBOM with cosign keyless OIDC
6. Uploads to the release

Manual regeneration: trigger `SBOM Generation` workflow manually with the release tag as input.

## Scope

The SBOM covers:

- The mythos-agent npm package itself
- All production dependencies (transitive included) per the published `package.json` / `package-lock.json`

The SBOM does **not** cover:

- Development-only dependencies (test runners, linters, type-checkers)
- External tools that mythos-agent invokes via subprocess (Semgrep, Trivy, Gitleaks, Checkov, Nuclei) — these are user-installed and tracked in their own SBOMs
- The Docker image layers — a separate Docker SBOM lands in H2 2026
- LLM model weights — these are user-fetched and not redistributed

## Verifying an SBOM

Downstream Manufacturers verifying SBOM integrity:

```bash
# Download the SBOM, signature, and certificate from the release page
cosign verify-blob \
  --certificate mythos-agent-sbom.cdx.json.crt \
  --signature   mythos-agent-sbom.cdx.json.sig \
  --certificate-identity-regexp 'https://github.com/mythos-agent/mythos-agent/.github/workflows/sbom\.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  mythos-agent-sbom.cdx.json
```

If verification fails, treat the SBOM as untrusted and report at [SECURITY.md](../../SECURITY.md).

## Why CycloneDX, not SPDX

CycloneDX:

- Has tooling that already produces accurate npm SBOMs out of the box
- Is the format most commonly required by EU CRA-related downstream contracts in 2026
- Supports vulnerability annotations (we plan to embed VEX statements once Theme A's deterministic taint engine ships)

We are open to adding SPDX output if a downstream Manufacturer asks for it; open an issue.

## How this maps to EU CRA

Under the EU Cyber Resilience Act, a Manufacturer placing a product on the EU market must include an SBOM covering the product's components. When you integrate mythos-agent into such a product, our SBOM gives you:

- A machine-readable component list to merge into your product's SBOM
- License metadata for each dependency (sufficient for CRA Annex II)
- Cryptographic provenance via cosign signature (sufficient for CRA Annex I component integrity)

See [`docs/security/cra-stance.md`](cra-stance.md) for the full role declaration.

## Retention and history

- Release-attached SBOMs are retained for the lifetime of the release (no expiry)
- CI-artifact SBOMs are retained 365 days
- Pre-release versions (`alpha`, `beta`, `rc`) are also published with SBOMs

If a release is yanked from npm, the SBOM remains on the GitHub release for forensic reference but is annotated as "yanked release — do not deploy."

## Reporting an SBOM issue

If you find an SBOM that:

- Lists a component that is not actually included
- Omits a component that is actually included
- Has a signature verification failure

Open an issue with the `sbom` label, or — if the issue suggests tampering — report via [SECURITY.md](../../SECURITY.md).

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial publication. |
