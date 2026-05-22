# Design — Tier 0 Capability Quick-Wins Bundle

**Date:** 2026-05-22
**Issue trail:** capability review of 2026-05-22 (4-agent parallel deep-dive); roadmap Tier 0. Goal: raise mythos-agent's real-bug find rate *per dollar*. Related: `docs/path-forward.md` Tracks A–E.
**Status:** approved, pending implementation plan.

## TL;DR

Four small, high-leverage changes that make hunting cheaper and smarter, with no new subsystems:

1. **Prompt caching** in the shared Anthropic client — 5–10× input-token cost cut on every agentic loop.
2. **Wire `createAdvancedTools`** (call-graph, caller/callee, endpoint mapping) into the recon/hypothesis/analyzer loops — gives agents interprocedural reasoning they currently lack.
3. **Expand the variant seed corpus** 5 → 11 (+6 hand-curated CVE patterns).
4. **Fix silent-failure JSON parsing** in the agent loops — stop discarding real findings.

## Background

A 2026-05-22 capability review (4 parallel agents) found mythos-agent is currently "a competent known-anti-pattern linter, structurally incapable of finding a novel 0-day" — but that powerful machinery is already built and simply not wired in. The Tier 0 bundle is the cheap, compounding first step: it does **not** remove the syntactic ceiling (that is Tier 1 — differential fuzzer, real AST/taint), but it makes every subsequent experiment 5–10× cheaper and every hunt meaningfully smarter.

Three of the four items are wiring/robustness fixes to existing, tested code. Only Item 3 adds new content.

## Scope

### In scope

The four items below: prompt caching, advanced-tool wiring, +6 seeds, parsing robustness.

### Out of scope

- `submit_findings` structured-tool redesign — deferred to Tier 1.
- Sandbox, differential fuzzer, real AST / sound taint — Tier 1 capability multipliers.
- Any change that deepens the AST matcher's expressiveness — Tier 1.
- A broad seed expansion (+15–20) — deliberately scoped to a focused +6.

## Item 1 — Prompt caching

**Problem.** No `cache_control` anywhere in `src/` (confirmed by review). Every agentic loop re-sends the system prompt + tool definitions uncached on every turn (up to 15–20 turns). The stable prefix is re-billed at full input price each turn.

**Change.** Centralize caching in `src/llm/anthropic-client.ts` — the `AnthropicLLMClient` shared by *all* agentic loops (recon-agent, hypothesis-agent, analyzer, variant-analyzer all funnel through `createLLMClient` → this client; verified at `recon-agent.ts:4`). The client's `messages.create` is currently a pure pass-through (`anthropic-client.ts:22-25`); intercept `params` and apply `cache_control: {type:"ephemeral"}` to the stable prefix — the `tools` array and the `system` prompt — leaving the growing `messages` transcript uncached.

`src/agent/providers/anthropic.ts` (`AnthropicProvider`, a separate abstraction) gets the same marker *only if* implementation confirms it is on a hot path; otherwise skipped.

**Expected.** 5–10× input-token cost reduction on agentic loops (Anthropic ephemeral cache, 5-min TTL). Directly raises runs-per-dollar.

**Verify.** `usage.cache_read_input_tokens` > 0 on turn ≥2 of a loop; A/B a variants-calibration run cost before/after.

**Implementation note.** Use the `claude-api` skill — it covers the exact `cache_control` placement mechanics (system-as-array of blocks vs. last-tool marker) and is the project's standard for Anthropic SDK work.

## Item 2 — Wire advanced tools into hunt agents

**Problem.** `createAdvancedTools` (`tools-advanced.ts:39`) and `executeAdvancedToolCall` (`tools-advanced.ts:153`) provide call-graph tracing, caller/callee lookup, and endpoint mapping — built and tested, but imported by zero hunt agents. The recon/hypothesis/analyzer loops use only `createAgentTools` (the four basic grep/read tools), so they cannot follow a data flow across function or file boundaries. The review named this the #1 false-negative source.

**Change.** In each of the three agent loops — recon-agent.ts (tools built at `recon-agent.ts:49`), hypothesis-agent.ts, and analyzer.ts — merge the toolsets (`[...createAgentTools(p), ...createAdvancedTools(p)]`) and update the tool-dispatch to route advanced tool names to `executeAdvancedToolCall`, falling through from `executeToolCall`.

**Expected.** Agents gain interprocedural reasoning; higher recall on multi-file source→sink bugs (IDOR, auth bypass, cross-file taint).

**Verify.** A `hunt` run on `demo-vulnerable-app/` shows advanced tools (`list_functions`, call-graph, endpoint tools) invoked in the turn log.

**Risk.** More tools = larger tool-definition block per request — mitigated by Item 1 (the tool block is in the cached prefix).

## Item 3 — Expand the variant seed corpus

**Problem.** `seed-patterns.ts` has 5 hand-curated `RootCausePattern` seeds → variants v2 can only search for 5 bug classes.

**Change.** Add 6 hand-derived seeds to the `SEEDS` array (`seed-patterns.ts:29`), each from a real CVE fix commit, preserving the file's "ground truth, not LLM-generated" rule (header comment, `seed-patterns.ts:22-25`):

1. Prototype pollution (CWE-1321)
2. Command injection (CWE-78)
3. Path traversal (CWE-22)
4. SSRF (CWE-918)
5. SQL injection (CWE-89)
6. XXE (CWE-611)

Each seed: pick a well-documented CVE, read its fix commit, fill `bugClass / cwe / astShape / dataFlow / summary`.

**Expected.** Variants v2 searchable seed count 5 → 11 (the existing 5 cover 4 distinct classes — two are ReDoS variants — so this roughly doubles distinct-bug-class coverage).

**Verify.** Each new seed gets a known-vulnerable case it should hit (a small fixture or a real vulnerable-commit checkout), calibration-style — analogous to the existing A3 corpus.

**Out of scope here.** The AST matcher's inability to express data-flow constraints (Tier 1) — new seeds inherit the current matcher's expressiveness limits. This item widens coverage; it does not deepen matching.

## Item 4 — Fix silent-failure parsing

**Problem.** Agent loops extract JSON from the model's final text with a greedy `text.match(/\{[\s\S]*\}/)`. Greedy `{...}` grabs the outermost braces — prose containing a JSON example, or two JSON objects, breaks it. On parse failure or MAX_TURNS exhaustion the loop silently returns an empty fallback. A real bug reported on turn 21, or wrapped in slightly malformed JSON, is discarded with no signal.

**Change.**

- Replace the greedy regex with a brace-balanced, string-aware JSON extractor (scan for the first `{`, track depth ignoring braces inside string literals, return the balanced span, then `JSON.parse`). Apply at every `parseX` site: `analyzer.ts`, `recon-agent.ts`, `hypothesis-agent.ts`, `exploit-agent.ts`.
- On parse failure or MAX_TURNS exhaustion, emit an explicit warning (console + a structured field on the returned report) instead of silently returning the empty fallback.

**Expected.** Real findings stop being silently dropped; failures become visible.

**Verify.** Unit tests for the extractor with adversarial inputs: prose-wrapped JSON, two JSON objects, truncated JSON, JSON with nested braces inside string values. Exhaustion path emits a warning.

## Success criteria

| Item | Done when |
|---|---|
| 1 | `cache_read_input_tokens` > 0 in an agentic loop; cost A/B shows the cut |
| 2 | advanced tools appear in a `hunt` turn log on `demo-vulnerable-app/` |
| 3 | 6 new seeds in `seed-patterns.ts`, each with a passing calibration case |
| 4 | adversarial-input unit tests pass; exhaustion/parse-failure surfaced |

## Risks & mitigations

- **Caching markers placed wrong → no cache hits.** Use the `claude-api` skill; verify via `cache_read_input_tokens`.
- **Advanced tools slow down or confuse the loop.** Tools are already tested; the merge is per-agent and individually revertable if a loop regresses.
- **Seed hand-curation quality.** Each seed is validated against a known case before it counts as done; 6 is a deliberately focused number.
- **Brace-balanced extractor edge cases** (braces inside string literals). The extractor must be string-aware; covered by the adversarial unit tests.

## Testing & integration notes

- Existing tests (`npm test` / `vitest run`) must stay green; `npx tsc --noEmit` clean.
- Commits in this repo require a DCO `Signed-off-by:` trailer (`git commit --signoff`) — CI fails without it.
- Conventional-commits enforced (commitlint) — commit messages must follow the `type(scope): subject` form.

## Sequencing

Items are independent and can land as separate commits/PRs. Recommended order: **1 (caching) → 4 (parsing) → 2 (tool wiring) → 3 (seeds)** — caching first so all later verification runs are cheap; parsing second so later runs surface failures honestly; tool wiring and seeds last as the find-rate-lifting changes.
