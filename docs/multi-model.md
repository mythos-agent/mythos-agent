# Multi-Model Support — tier system & rollout

> **Status:** stage 1 of 3 shipped (the `baseURL` config field).
> Stages 2 and 3 are tracked below with their start triggers.
> **Last reviewed:** 2026-04-26.

This document is the canonical reference for how mythos-agent supports — and *honestly* describes its support for — multiple LLM providers. The README links here for the long-form policy.

## Why multi-model

Three pressures, all real:

1. **Cost.** A single hunt run on Claude Sonnet 4.6 costs roughly $1–$5 per target (per `docs/security/outbound-disclosure.md` § Cost & time budget). Qwen via DashScope or local Ollama is roughly an order of magnitude cheaper, in some configurations free.
2. **Vendor independence.** Single-provider lock-in is operational risk for users (rate limits, pricing changes, ToS shifts) and adoption friction for the project.
3. **Privacy.** "This code never leaves my network" is a legitimate use case for a security tool reviewing internal/proprietary code. Local models (Ollama, LM Studio, vLLM) are the only answer.

The 2026 OSS coding-agent peer set (Aider, Continue, OpenCode, Kilo Code, Qwen Code, OpenHands) treats multi-provider support as table stakes, not a differentiator. Anthropic-only positioning in 2026 reads as pre-MVP or vendor-tied.

## The tier system

The catch is that "supports N providers" without acknowledging quality differentials becomes the kind of marketing that erodes trust. mythos-agent uses an explicit tier system:

| Tier | Providers | Commitment | Guarantees |
|---|---|---|---|
| **Tier 1: Primary** | Anthropic (Claude Sonnet / Opus / Haiku) | Fully tested. Primary CI target. System prompts tuned for Claude. Published catch-rate numbers in [`docs/benchmarks/external-scores.md`](benchmarks/external-scores.md) are produced with this tier. | Catch rates as published. New scanner work tested here first. |
| **Tier 2: Compatible** | Anything OpenAI-compatible — OpenAI itself, Qwen (DashScope/OpenRouter), Gemini, Mistral, vLLM, Ollama, LM Studio, LiteLLM-proxied anything. | Wired via single OpenAI SDK code path with `baseURL` + `model` config. Compatibility-tested in CI; not full feature parity. | Hunt pipeline runs end-to-end. Catch rates may differ; will be published per-provider in a comparison table once stage 3 lands. |
| **Tier 3: Local / community** | Local Ollama / LM Studio / vLLM specifically (also Tier 2 technically). | Same code path as Tier 2; called out separately in docs because the privacy / cost-of-zero properties are the use case. | Best-effort. May underperform on agentic tool-use loops; depends on local model size. |

**Why not "fully supports all providers equally":** catch quality matters more than breadth in security tooling. A claim like "we caught CVE-X" needs to hold across the supported set, or every claim needs an asterisk. The OpenCode 75-model / Kilo Code 500-model posture is right for general coding agents but the wrong axis for a security tool.

**Why not "Anthropic-only forever":** the peer set's bar makes Anthropic-only feel pre-MVP in 2026, and it excludes the cost-sensitive and privacy-sensitive user segments.

## Stage 1: `baseURL` config (shipped)

**What it does.** Adds `baseURL?: string` to `MythosConfig`. The Anthropic SDK constructor in each of the four agents now passes `baseURL` through. Users can set it via:

- `.mythos.yml`:
  ```yaml
  apiKey: <provider-key>
  baseURL: http://localhost:4000  # or https://openrouter.ai/api/v1, etc.
  ```
- Env var: `MYTHOS_BASE_URL=...` or `ANTHROPIC_BASE_URL=...` (the Anthropic SDK auto-reads the latter; mythos-agent reads either explicitly).
- File-set value wins over env (matches the file-precedence contract for non-secret fields).

**What this unblocks.** Any Anthropic-compatible proxy. Concrete recipes:

- **LiteLLM proxying to Qwen:**
  ```bash
  litellm --model dashscope/qwen-3-30b --port 4000  # in one terminal
  export ANTHROPIC_BASE_URL=http://localhost:4000
  export ANTHROPIC_API_KEY=<dashscope-key>
  npx mythos-agent@latest hunt ./your-target
  ```
- **OpenRouter (any model on their roster):**
  ```bash
  export ANTHROPIC_BASE_URL=https://openrouter.ai/api/v1
  export ANTHROPIC_API_KEY=<openrouter-key>
  npx mythos-agent@latest hunt ./your-target
  ```
- **AWS Bedrock with Anthropic models:** point `baseURL` at the Bedrock endpoint per AWS docs.

**What this doesn't do.** It does not provide native, direct support for OpenAI / Qwen / Gemini SDKs. All Tier 2 use today goes through an Anthropic-format-speaking proxy. Native OpenAI SDK support lands in stage 2.

**Quality caveat.** Tool-use protocol translation (Anthropic `tool_use` blocks → OpenAI `tool_calls` → back) introduces edge cases. Some hunt runs through a proxy may degrade vs. native Tier 1; track findings via the CVE Replay scoreboard (which currently runs Tier 1 only).

## Stage 2: native OpenAI SDK code path (in progress)

**Trigger satisfied 2026-04-26:** Qwen-via-LiteLLM-proxy verified working end-to-end on `demo-vulnerable-app/` (10 entry points correctly identified, 34 findings produced, 6 chains, 8 PoCs, ~3 min runtime). Stage 2 is in progress; tracked in issue #43.

**Sub-PR sequence:**

- [x] **2a — `LLMClient` abstraction interface + AnthropicClient adapter.** Refactor only, zero behavior change. `src/llm/llm-client.ts` + `src/llm/anthropic-client.ts`. Migrates `src/agent/analyzer.ts` to use the abstraction. (Shipped alongside 2b/2c-partial in the proof-of-pattern PR.)
- [x] **2b — OpenAIClient adapter implementing the same interface.** `src/llm/openai-client.ts`. Translates the 5 differences (system message, content blocks, tool defs, tool-result threading, stop reasons). Unit tests with mocked OpenAI responses cover the translation matrix.
- [x] **2c (partial) — wired into `analyzer.ts` only.** `recon-agent.ts`, `hypothesis-agent.ts`, `exploit-agent.ts` still construct `Anthropic` directly; their migration follows in subsequent PRs (one per agent or bundled).
- [ ] **2c (rest) — wire into the remaining 3 agents.** Same pattern as analyzer.ts.
- [ ] **2d — update this doc to mark stage 2 fully shipped.** Stage 3 trigger fires once 2c is complete and at least one Tier 2 catch rate is measured.

**Configuration:** when `provider !== "anthropic"` in `MythosConfig`, the factory `createLLMClient(config)` returns an `OpenAILLMClient` instead of `AnthropicLLMClient`. Example:

```yaml
# .mythos.yml — Qwen via DashScope's OpenAI-compatible endpoint
provider: openai
apiKey: <dashscope-key>
baseURL: https://dashscope.aliyuncs.com/compatible-mode/v1
model: qwen-plus
```

No LiteLLM in the loop. The translation happens inside `OpenAILLMClient` between the agent layer's Anthropic-shaped requests and the OpenAI SDK.

**Live verification.** Unit tests cover the translation logic with mocked responses (`src/llm/__tests__/openai-client.test.ts`, 25 tests). Live verification requires a real Tier 2 provider key; no live API in CI. Recommended sequence after each sub-PR lands: set `provider: openai` + `baseURL` + `apiKey` + `model`, run `npx mythos-agent@latest hunt ./demo-vulnerable-app --json`, confirm all 4 phases complete and entry-point recon is non-empty, compare to a Tier 1 (Anthropic) run for catch-rate sanity.

## Stage 3: cross-provider scoreboard + tier docs (planned)

**Trigger to start:** stage 2 ships AND at least one Tier 2 provider's catch rate is measured.

**What it will ship.** Extends the CVE Replay harness with a `--provider` flag; the scoreboard table ([`docs/benchmarks/external-scores.md`](benchmarks/external-scores.md)) grows columns per provider. The README's "AI Providers" section gets the full tier-system rewrite. Removes the false-equivalence list of providers from the README.

The benchmark numbers are what justify the tier-system claims. Without them, the tier system is just opinion.

## What we explicitly don't do

- **Build a custom provider-abstraction layer.** OpenAI SDK + Anthropic SDK is two of the best-known shapes; rolling our own abstraction on top is the kind of premature framework that always rots. Two narrow code paths is enough; revisit only if a third Tier 2 SDK is needed and the duplication becomes load-bearing.
- **Recommend a single proxy.** LiteLLM, OpenRouter, Vercel AI Gateway, and Bifrost all work via the `baseURL` config. The choice between them is operational (cost, performance, governance features) and depends on the user's environment. mythos-agent's docs describe the capability; the choice is yours.
- **MCP-tool-format support for the agents.** The agents currently use Anthropic-format `tool_use` blocks; MCP-format tool definitions are a separate axis. Worth doing eventually — but blocked on the Agentic AI Foundation interoperability spec stabilizing (still in flight as of December 2025 launch).
- **Switch the project's primary CI testing target off Anthropic.** Tier 1 stays Anthropic — published catch-rate numbers are produced there; the cost / perf / quality tradeoff makes Anthropic the right primary target for a security tool whose value depends on agent reasoning quality.

## See also

- [`README.md`](../README.md) § AI Providers — the user-facing summary
- [`docs/security/outbound-disclosure.md`](security/outbound-disclosure.md) — Phase B context that motivates lower-cost providers
- [`docs/benchmarks/external-scores.md`](benchmarks/external-scores.md) — where the tier-2 comparison table will land in stage 3
