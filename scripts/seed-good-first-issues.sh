#!/usr/bin/env bash
# scripts/seed-good-first-issues.sh
#
# Bulk-opens good-first-issue tickets for the H1 2026 "80% CLI test coverage"
# campaign. One issue per untested CLI command. Uses the GitHub CLI (`gh`).
#
# Usage:
#   ./scripts/seed-good-first-issues.sh [--dry-run]
#
# Requirements:
#   - gh CLI installed and authenticated (gh auth status)
#   - Run from repository root
#   - The labels `good-first-issue` and `test` must exist on the repo
#
# What it does:
#   1. Lists every src/cli/commands/*.ts that does NOT have a sibling
#      __tests__/ directory.
#   2. For each, opens an issue titled
#      "test(cli): add Vitest suite for `<command>`"
#      with a body that points to the testing policy and a worked example.
#   3. Stops if any `gh issue create` fails (don't half-seed).
#
# Idempotency: re-running this script will create duplicate issues. Run once
# (or use --dry-run first to preview) and check the issue tracker before
# rerunning.

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

# Verify we're at the repo root
if [[ ! -f "package.json" ]] || [[ ! -d "src/cli/commands" ]]; then
  echo "ERROR: run from sphinx-agent repository root" >&2
  exit 1
fi

# Verify gh is available and authenticated
if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: gh CLI is not installed. https://cli.github.com/" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "ERROR: gh CLI is not authenticated. Run 'gh auth login'." >&2
  exit 1
fi

# Enumerate untested CLI commands
mapfile -t COMMANDS < <(
  for f in src/cli/commands/*.ts; do
    name=$(basename "$f" .ts)
    # If a __tests__ directory next to commands/ has a matching test file, skip
    if [[ -f "src/cli/commands/__tests__/${name}.test.ts" ]] || \
       [[ -f "src/cli/commands/__tests__/${name}.spec.ts" ]]; then
      continue
    fi
    echo "$name"
  done
)

if [[ ${#COMMANDS[@]} -eq 0 ]]; then
  echo "All CLI commands appear to have tests. Nothing to seed."
  exit 0
fi

echo "Will seed ${#COMMANDS[@]} good-first-issue tickets:"
for cmd in "${COMMANDS[@]}"; do
  echo "  - $cmd"
done

if [[ "$DRY_RUN" == "true" ]]; then
  echo
  echo "DRY RUN — no issues created."
  exit 0
fi

read -rp "Proceed and create these issues? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

# Open the issues
for cmd in "${COMMANDS[@]}"; do
  TITLE="test(cli): add Vitest suite for \`${cmd}\`"
  BODY=$(cat <<EOF
## Task

Add a Vitest test suite for the \`${cmd}\` CLI command at \`src/cli/commands/${cmd}.ts\`.

This is part of the H1 2026 "80% CLI test coverage" bucket. See the pinned [\`[Roadmap] sphinx-agent H1 2026 Goals\`](../../issues?q=is%3Aissue+is%3Aopen+%22%5BRoadmap%5D%22) issue.

## Acceptance criteria

- [ ] Test file at \`src/cli/commands/__tests__/${cmd}.test.ts\` (or \`.spec.ts\`)
- [ ] Tests cover the happy path
- [ ] Tests cover at least one error / edge case
- [ ] \`npm test\` passes locally and in CI
- [ ] No new ESLint or TypeScript warnings introduced

## Where to look

- The command implementation: \`src/cli/commands/${cmd}.ts\`
- Existing scanner tests for inspiration: \`src/scanner/__tests__/\`
- Testing policy: [CONTRIBUTING.md § Testing policy](../blob/main/CONTRIBUTING.md#testing-policy)
- Demo fixtures (use freely): \`demo-vulnerable-app/\`

## Why this matters

Right now \`${cmd}\` has no automated tests. A regression here would ship to npm without warning. Closing this issue tightens the safety net for the whole CLI surface.

## Recognition

Merging this PR earns a [Sphinx Mythos Pioneer](../blob/main/docs/pioneers.md) badge in the **🧪 Test** category.

## Notes for reviewer

- Test should mock external IO (filesystem, network) where possible
- For commands that invoke an LLM, mock the provider in \`src/agent/providers/\` rather than running the real call
EOF
)
  echo "Creating: $TITLE"
  gh issue create \
    --title "$TITLE" \
    --body "$BODY" \
    --label "good-first-issue" \
    --label "test" \
    --label "h1-2026-goals"
done

echo
echo "Seeded ${#COMMANDS[@]} good-first-issues."
echo "Next: pin the [Roadmap] H1 2026 Goals issue if not already pinned."
