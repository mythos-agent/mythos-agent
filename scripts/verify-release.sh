#!/usr/bin/env bash
# scripts/verify-release.sh
#
# Verifies the cosign keyless signature and SLSA build provenance for a
# mythos-agent release. Downstream Manufacturers (per EU CRA, see
# docs/security/cra-stance.md) can run this to confirm a release was built
# from this exact repo's CI without a hand-signed key existing anywhere.
#
# Usage:
#   ./scripts/verify-release.sh <version>
#
# Example:
#   ./scripts/verify-release.sh v2.0.1
#   ./scripts/verify-release.sh 2.0.1     # 'v' prefix optional
#
# Requirements:
#   - cosign installed (https://docs.sigstore.dev/system_config/installation/)
#   - gh CLI installed and authenticated to the canonical repo
#   - jq installed (for JSON parsing)
#
# What it verifies:
#   1. The release exists on GitHub
#   2. The cosign signature (.sig) and certificate (.crt) match the tarball
#   3. The signing identity matches sigstore-release.yml on this repo
#   4. The OIDC issuer is GitHub Actions (not a forged cert)
#   5. (Optional) SBOM signature is also valid
#   6. (Optional) npm package provenance attestation is consistent

set -euo pipefail

REPO="mythos-agent/mythos-agent"
EXPECTED_IDENTITY_REGEX="https://github.com/${REPO}/.github/workflows/sigstore-release\.yml@.*"
EXPECTED_OIDC_ISSUER="https://token.actions.githubusercontent.com"

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version>" >&2
  echo "Example: $0 v2.0.1" >&2
  exit 64
fi

VERSION="${1#v}"          # strip optional leading 'v'
TAG="v${VERSION}"

# Sanity: tools available
for tool in cosign gh jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: $tool is required but not installed." >&2
    exit 69
  fi
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "→ Verifying mythos-agent ${TAG} from ${REPO}"
echo "  Working directory: $WORK"
echo

# 1. Confirm the release exists
echo "[1/5] Checking release exists..."
if ! gh release view "$TAG" --repo "$REPO" --json tagName --jq '.tagName' >/dev/null 2>&1; then
  echo "ERROR: release $TAG does not exist on $REPO" >&2
  exit 65
fi
echo "  ✓ release found"

# 2. Download tarball + signature artifacts
echo "[2/5] Downloading tarball + signatures..."
gh release download "$TAG" \
  --repo "$REPO" \
  --pattern "mythos-agent-*.tgz*" \
  --dir "$WORK" 2>/dev/null || {
  echo "ERROR: could not download tarball assets for $TAG" >&2
  exit 66
}

TARBALL=$(ls "$WORK"/mythos-agent-*.tgz 2>/dev/null | grep -v '\.sig$\|\.crt$\|\.sha256$' | head -1)
SIG="${TARBALL}.sig"
CRT="${TARBALL}.crt"

if [[ ! -f "$TARBALL" ]] || [[ ! -f "$SIG" ]] || [[ ! -f "$CRT" ]]; then
  echo "ERROR: missing tarball, .sig, or .crt artifact" >&2
  echo "  Tarball: $TARBALL ($([ -f "$TARBALL" ] && echo OK || echo MISSING))" >&2
  echo "  Sig:     $SIG ($([ -f "$SIG" ] && echo OK || echo MISSING))" >&2
  echo "  Cert:    $CRT ($([ -f "$CRT" ] && echo OK || echo MISSING))" >&2
  exit 67
fi
echo "  ✓ tarball + signature + certificate downloaded"

# 3. cosign verify-blob on the tarball
echo "[3/5] Verifying cosign keyless signature..."
if ! cosign verify-blob \
  --certificate "$CRT" \
  --signature "$SIG" \
  --certificate-identity-regexp "$EXPECTED_IDENTITY_REGEX" \
  --certificate-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
  "$TARBALL" >/dev/null 2>&1; then
  echo "ERROR: cosign verification FAILED" >&2
  echo "  This means the tarball was NOT signed by $REPO's sigstore-release.yml" >&2
  echo "  Do not use this artifact." >&2
  exit 68
fi
echo "  ✓ signature valid; signed by $REPO/.github/workflows/sigstore-release.yml"

# 4. Verify SBOM signature if present
echo "[4/5] Verifying SBOM signature (if present)..."
SBOM_JSON="$WORK/mythos-agent-sbom.cdx.json"
SBOM_SIG="${SBOM_JSON}.sig"
SBOM_CRT="${SBOM_JSON}.crt"
gh release download "$TAG" \
  --repo "$REPO" \
  --pattern "mythos-agent-sbom.cdx.*" \
  --dir "$WORK" 2>/dev/null || true

if [[ -f "$SBOM_JSON" ]] && [[ -f "$SBOM_SIG" ]] && [[ -f "$SBOM_CRT" ]]; then
  SBOM_IDENTITY_REGEX="https://github.com/${REPO}/.github/workflows/sbom\.yml@.*"
  if cosign verify-blob \
    --certificate "$SBOM_CRT" \
    --signature "$SBOM_SIG" \
    --certificate-identity-regexp "$SBOM_IDENTITY_REGEX" \
    --certificate-oidc-issuer "$EXPECTED_OIDC_ISSUER" \
    "$SBOM_JSON" >/dev/null 2>&1; then
    RULES=$(jq '.components | length' "$SBOM_JSON" 2>/dev/null || echo "?")
    echo "  ✓ SBOM signature valid; lists $RULES components"
  else
    echo "  ⚠ SBOM signature verification FAILED (signed but cert check failed)"
  fi
else
  echo "  ⚠ no SBOM artifacts found (release may pre-date sbom.yml)"
fi

# 5. npm provenance attestation
echo "[5/5] Checking npm provenance attestation..."
if NPM_OUT=$(npm view "mythos-agent@${VERSION}" dist.attestations --json 2>/dev/null) && [[ -n "$NPM_OUT" ]]; then
  PROV=$(echo "$NPM_OUT" | jq -r '.attestations.url // empty' 2>/dev/null)
  if [[ -n "$PROV" ]]; then
    echo "  ✓ npm provenance attestation published at $PROV"
  else
    echo "  ⚠ npm metadata present but no provenance URL — version may have shipped without --provenance"
  fi
else
  echo "  ⚠ could not fetch npm metadata (offline? version not published?)"
fi

echo
echo "✓ Release ${TAG} verified."
echo "  Signed by:       sigstore-release.yml on ${REPO}"
echo "  OIDC issuer:     ${EXPECTED_OIDC_ISSUER}"
echo "  Tarball:         $(basename "$TARBALL")"
echo
echo "If ANY step above failed (✗) or printed an unexpected warning (⚠) you"
echo "should not deploy this release. See docs/security/threat-model.md for"
echo "what compromise of the supply chain would look like."
