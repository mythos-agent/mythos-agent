# Tree-sitter grammars

Prebuilt tree-sitter grammar `.wasm` files used by `src/analysis/ast-matcher/`
to parse target codebases (sub-PR A2 of variants v2 — see
`docs/path-forward.md` Track A).

## Files

| File                            | Source                                                                       | Upstream license |
| ------------------------------- | ---------------------------------------------------------------------------- | ---------------- |
| `tree-sitter-javascript.wasm`   | `@vscode/tree-sitter-wasm@0.3.1` → upstream `tree-sitter-javascript`         | MIT              |
| `tree-sitter-typescript.wasm`   | `@vscode/tree-sitter-wasm@0.3.1` → upstream `tree-sitter-typescript`         | MIT              |

The `@vscode/tree-sitter-wasm` distribution itself is MIT-licensed; each
individual grammar is MIT-licensed by its upstream maintainer. mythos-agent
re-distributes only the two grammar binaries above and is unmodified from the
`@vscode/tree-sitter-wasm@0.3.1` build.

> **ABI note:** `web-tree-sitter@0.26` requires the WASM `dylink.0`
> custom-section format (newer Emscripten). Older builds (e.g.
> `tree-sitter-wasms@0.1.13`, which ships `dylink`) load with status
> `"need dylink section"` from `getDylinkMetadata`. Always source
> grammars from a build that targets the same WASM ABI as the
> installed `web-tree-sitter`.

## How to refresh

```sh
npm pack @vscode/tree-sitter-wasm@<version> --pack-destination /tmp/
tar -xzf /tmp/vscode-tree-sitter-wasm-<version>.tgz \
  package/wasm/tree-sitter-javascript.wasm \
  package/wasm/tree-sitter-typescript.wasm
cp package/wasm/*.wasm assets/grammars/
```

Bumping the version: re-run the `ast-matcher` test suite. Tree-sitter
grammar bumps occasionally rename node kinds, which would break A1's
seed `astShape.kind` strings. The seed corpus is the canonical reference
for which kinds we depend on; if a kind disappears, update both the
seed and the grammar in the same PR.
