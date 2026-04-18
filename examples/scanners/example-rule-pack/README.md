# mythos-agent-rules-example

A cookie-cutter rule pack for mythos-agent. Copy this directory, rename, and publish to npm under the `mythos-agent-rules-*` prefix.

> **What this is:** the YAML rule-pack pattern, available **today**. For programmatic scanners, see the [Scanner SDK spec](../../../docs/scanner-sdk.md) (specification published; SDK implementation lands Q3 2026).

## Layout

```
mythos-agent-rules-example/
├── README.md           # This file
├── package.json        # npm metadata; declares as a mythos-agent rule pack
├── rules.yml           # The actual rules
└── tests/
    └── rules.test.js   # Unit tests for true positives + negatives
```

## How a rule pack is loaded

When a user installs your package alongside mythos-agent:

```bash
npm install -g mythos-agent-rules-example
```

mythos-agent enumerates installed packages matching `mythos-agent-rules-*` at scan time and loads each pack's `rules.yml`. Packs can be enabled or disabled per-project in `.mythos-agent/config.json`:

```json
{
  "rulePacks": {
    "mythos-agent-rules-example": "enabled"
  }
}
```

## Writing a rule

Rules are declarative. Each rule needs a stable id, a real CWE (no `CWE-XXX` placeholders), severity, languages it applies to, and at least one pattern.

Open `rules.yml`, edit the example rule, and add your own. The repository's [CONTRIBUTING.md § Adding security rules](../../../CONTRIBUTING.md#adding-security-rules) is the canonical reference for the rule schema.

## Testing

Every rule must have at least one true-positive test (vulnerable code → match) and one true-negative test (safe code → no match). False-positive avoidance tests are particularly welcomed by the mythos-agent maintainers.

Run the tests:

```bash
cd mythos-agent-rules-example
npm install
npm test
```

The test runner uses mythos-agent's own scanner against fixture files — there is no separate test framework to learn.

## Publishing

```bash
npm version patch       # or minor/major
npm publish --access public
```

Once published:

1. Open a PR against the mythos-agent repository adding your pack to the [community rule packs registry](../../../docs/rule-packs.md) — placeholder; landing later H1 2026.
2. Tag a release on your own repo with cosign signing if you can — mythos-agent's [SBOM workflow pattern](../../../.github/workflows/sbom.yml) is a reusable starting point.
3. Add a `keywords: ["mythos-agent", "security", "rule-pack"]` field to `package.json` so npm search finds your pack.

## Recognition

Rule-pack maintainers count toward the [Mythos-Agent Pioneers](../../../docs/pioneers.md) once at least one of your rules is referenced from the main mythos-agent benchmark. The cash bounty program at [`docs/bounty.md`](../../../docs/bounty.md) is currently inactive but, once activated, rule-pack contributions are within scope.

## License

Rule packs SHOULD use an OSI-approved license. MIT (matching mythos-agent itself) is recommended. Closed-source rule packs cannot be loaded by mythos-agent's plugin discovery; the runtime requires a valid OSI license declaration in `package.json`.

## Trademark

The `mythos-agent-rules-*` and `mythos-agent-scanner-*` npm prefixes are reserved for community packs. Use them freely for genuine community contributions; do not use them to signal endorsement that hasn't been granted. See [GOVERNANCE.md § Trademark and Project Identity](../../../GOVERNANCE.md#trademark-and-project-identity).
