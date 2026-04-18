# Scanner Plugin SDK

> **Status: Specification (Q3 2026 milestone).** Today, scanners live inside the shedu repository and rule packs ship as YAML. This document specifies the future plugin SDK that lets external scanners ship as standalone npm packages.
>
> **Related:** the YAML rule-pack pattern (`shedu-rules-*`) is **already supported** today and is documented in [CONTRIBUTING.md § Rule packs](../CONTRIBUTING.md#rule-packs). Use that for declarative rules. The SDK below is for scanners that need real logic — taint summaries, AST traversal, or external-API enrichment.

## Why an SDK

The 49 scanners that ship inside shedu today were all written by the lead maintainer. As the contributor base grows, two pressures demand an out-of-tree extension surface:

1. **Velocity.** A bounty-funded scanner-rule contributor (per [`docs/bounty.md`](bounty.md)) should be able to ship a complete scanner without touching the core repo.
2. **Trust.** A scanner that touches the network or invokes an LLM provider needs an explicit declaration of capabilities so users can audit before installing. In-tree scanners get implicit trust; out-of-tree scanners need to earn it.

The SDK addresses both: a scanner is a standalone npm package, named `shedu-scanner-*`, that exports a typed `Scanner` interface, declares its capabilities in a manifest, and is loaded by shedu via plugin discovery.

## Distribution conventions

| Concern | Convention |
|---|---|
| **npm name** | `shedu-scanner-<topic>` for community scanners; `shedu-rules-<topic>` for declarative YAML rule packs (already in use today) |
| **License** | MIT recommended; the SDK contract requires an OSI-approved license for the plugin to load |
| **Discovery** | shedu enumerates installed packages matching the prefix; per-project enable/disable in `.shedu/config.json` |
| **Versioning** | semver; shedu declares a minimum SDK version; mismatched SDK versions log a warning and skip the scanner |
| **Trademark** | The `sphinx-` namespace is reserved for community community scanners and rule packs. See [GOVERNANCE.md § Trademark and Project Identity](../GOVERNANCE.md#trademark-and-project-identity). |

## Scanner contract (preview)

The exact TypeScript interface lands when the SDK ships. Today's specification:

```typescript
import type { Scanner, ScannerContext, Vulnerability } from "@shedu/sdk";

export const scanner: Scanner = {
  // Identity
  id: "shedu-scanner-example",
  name: "Example Scanner",
  description: "Demonstrates the scanner SDK contract.",
  version: "0.1.0",
  cwes: ["CWE-79"], // CWEs this scanner detects; required, no `CWE-XXX` placeholders

  // Declared capabilities (audited at install time)
  capabilities: {
    network: false,           // does this scanner make network calls?
    llm: false,               // does this scanner invoke an LLM provider?
    filesystem: "read-only",  // "read-only" | "scoped-write" | "none"
    subprocess: false,        // does this scanner spawn subprocesses?
  },

  // Languages / file globs the scanner applies to
  applies: {
    languages: ["typescript", "javascript"],
    globs: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"],
    excludeGlobs: ["**/node_modules/**"],
  },

  // The scanner itself
  async scan(ctx: ScannerContext): Promise<Vulnerability[]> {
    const findings: Vulnerability[] = [];
    for (const file of ctx.files) {
      const content = await ctx.readFile(file);
      // ... scanning logic ...
    }
    return findings;
  },
};
```

## Capability declaration and runtime enforcement

Capability declaration in the manifest is a **promise to the user**. The runtime enforces it:

- `network: false` → the plugin's process is started with network egress blocked (or its `fetch` / `http` modules patched to throw)
- `llm: false` → calls into the provider abstraction throw at runtime
- `filesystem: "read-only"` → the `ctx.writeFile` API is not provided
- `subprocess: false` → `child_process` calls throw

A scanner that **declares a capability** is allowed to use it, but the user sees the capability in the install prompt and in `shedu doctor` output. Downstream Manufacturers per the [EU CRA stance](security/cra-stance.md) need to be able to enumerate what plugins they have allowed and what those plugins can do.

A scanner that **uses a capability without declaring it** is a SDK contract violation; the runtime logs an error, drops the findings, and surfaces the violation in `shedu doctor`.

## Output schema

Every finding the scanner returns must conform to the existing [`Vulnerability` type](../src/types/index.ts). Key required fields:

| Field | Required | Notes |
|---|---|---|
| `id` | Yes | Stable identifier; survives across runs for suppression / baseline |
| `title` | Yes | Short, human-readable |
| `description` | Yes | What the vulnerability is and why it matters |
| `severity` | Yes | `critical` / `high` / `medium` / `low` / `info` |
| `cwe` | Yes | Real CWE; placeholders rejected at validation time |
| `file` | Yes | Relative path from `ctx.projectRoot` |
| `line` | Yes | 1-indexed |
| `evidence` | Yes | The matching code snippet or AST excerpt |
| `confidence` | Recommended | `high` / `medium` / `low`; drives FP-rate metrics |
| `references` | Recommended | Links to CVE entries, blog posts, or upstream docs |

Additional fields (`fix`, `taintSources`, `chainCandidate`) are optional but improve integration with the chain engine and validated-remediation pipeline.

## Lifecycle and isolation

Each scanner runs in an isolated worker (Node.js worker thread), with:

- **Memory limit:** 512 MB by default; configurable per-scanner
- **CPU time limit:** 60 seconds wall clock per scan; configurable per-scanner
- **No global state shared with shedu core**
- **No access to API keys or user config** beyond what `ScannerContext` exposes

A scanner that exceeds limits is killed; its partial findings are discarded; the failure is reported in the scan summary.

## Example scanner package

A working cookie-cutter ships at [`examples/scanners/example-rule-pack/`](../examples/scanners/example-rule-pack/) demonstrating the YAML rule-pack pattern available **today**. The programmatic SDK pattern shown above will land with a parallel example at `examples/scanners/example-scanner/` when the SDK itself ships in Q3 2026.

## Roadmap relationship

The Scanner SDK is part of [Theme C — Ecosystem & Scale](../ROADMAP.md#3-strategic-themes) in the strategic roadmap. Concrete H1 2026 milestone: **specification published** (this document). Q3 2026 milestone: **`@shedu/sdk` package shipped** with example scanner. Q4 2026 milestone: **first community-contributed scanner using the SDK** in production.

Until the SDK ships, contributors who want to add a scanner should:

1. **For declarative rules:** ship a `shedu-rules-*` YAML rule pack today (see [CONTRIBUTING.md § Rule packs](../CONTRIBUTING.md#rule-packs))
2. **For programmatic scanners:** open an issue describing the use case so the SDK design can accommodate it

## Open questions

These will be resolved in the implementation RFC for the SDK:

- How does the runtime sandbox `subprocess: true` scanners safely on Windows / macOS?
- How are scanner SDK breaking changes versioned and rolled out?
- Do we ship a CLI subcommand `shedu scanner test <package>` to dry-run a scanner against the demo-vulnerable-app fixture?
- How do `shedu-rules-*` packs and `shedu-scanner-*` packages cohabit in the same install?

Open the RFC at `docs/rfcs/NNNN-scanner-sdk.md` (template at [`docs/RFC-TEMPLATE.md`](RFC-TEMPLATE.md)) when the implementation work is ready to start.

## Document history

| Date | Change |
|---|---|
| 2026-04-18 | Initial specification published. SDK implementation tracked under H1 2026 Goals issue. |
