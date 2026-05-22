# Tier 0 Capability Quick-Wins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make mythos-agent's vulnerability hunting cheaper and smarter via four small changes — prompt caching, advanced-tool wiring, +6 variant seeds, and robust JSON parsing — without adding new subsystems.

**Architecture:** Three of four items are wiring/robustness fixes to existing, tested code; one adds hand-curated data. A new prompt-cache transform centralizes caching in the shared Anthropic client. A new string-aware JSON extractor replaces a fragile regex at four call sites. A new combined-toolset helper lets the three hunt agents reach call-graph/endpoint tools that already exist but were never imported.

**Tech Stack:** TypeScript (ESM, `.js` import specifiers), Node 22, vitest, `@anthropic-ai/sdk`, tree-sitter (via the existing `ast-matcher`).

**Spec:** `docs/superpowers/specs/2026-05-22-tier0-capability-quick-wins-design.md`

**Repo conventions (apply to every commit):**
- Every commit MUST include a DCO sign-off: use `git commit --signoff`. CI fails without the `Signed-off-by:` trailer.
- Commit messages MUST follow Conventional Commits (`type(scope): subject`) — commitlint is enforced.
- `npm test` runs the full vitest suite. A single file: `npx vitest run <path>`. Typecheck: `npx tsc --noEmit`.

---

## File Structure

**Create:**
- `src/agent/json-extract.ts` — string-aware brace-balanced JSON extractor (one responsibility: pull a parseable JSON object out of model text).
- `src/agent/hunt-tools.ts` — combined toolset + dispatcher for hunt agents (basic tools + advanced tools, routed by name).
- `src/llm/__tests__/anthropic-client.test.ts` — tests for the prompt-cache transform.
- `src/agent/__tests__/json-extract.test.ts` — tests for the JSON extractor.
- `src/agent/__tests__/hunt-tools.test.ts` — tests for the combined toolset.
- `src/analysis/root-cause/__tests__/fixtures/` — 6 small vulnerable-code fixtures for the new seeds (Task 6).

**Modify:**
- `src/llm/anthropic-client.ts` — add and apply the `withPromptCache` transform.
- `src/agents/recon-agent.ts` — use `extractJson`; use `createHuntAgentTools`/`executeHuntToolCall`; warn on exhaustion.
- `src/agents/hypothesis-agent.ts` — same three changes.
- `src/agent/analyzer.ts` — same three changes.
- `src/agents/exploit-agent.ts` — use `extractJson`; warn on parse failure (no loop here).
- `src/analysis/root-cause/seed-patterns.ts` — add 6 `RootCausePattern` seeds.

---

## Task 1: Prompt caching in the shared Anthropic client

**Why:** No `cache_control` exists anywhere in `src/`. Every agentic loop (recon, hypothesis, analyzer, variant-analyzer — all funnel through `AnthropicLLMClient`) re-sends the system prompt + tool definitions uncached on every turn. Marking that stable prefix with an ephemeral cache breakpoint cuts input cost 5–10×.

**Files:**
- Modify: `src/llm/anthropic-client.ts`
- Test: `src/llm/__tests__/anthropic-client.test.ts`

**Optional sub-skill:** invoke the `claude-api` skill before implementing — it is the project standard for Anthropic SDK work and will confirm `cache_control` placement against the current SDK. The code below is correct as written; the skill is a verification backstop.

- [ ] **Step 1: Write the failing test**

Create `src/llm/__tests__/anthropic-client.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { withPromptCache } from "../anthropic-client.js";

describe("withPromptCache", () => {
  it("converts a string system prompt into a cached text block", () => {
    const out = withPromptCache({
      model: "claude-sonnet-4-6",
      max_tokens: 100,
      system: "You are a helper.",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(out.system).toEqual([
      { type: "text", text: "You are a helper.", cache_control: { type: "ephemeral" } },
    ]);
  });

  it("marks the last tool with cache_control and leaves earlier tools alone", () => {
    const out = withPromptCache({
      model: "claude-sonnet-4-6",
      max_tokens: 100,
      messages: [{ role: "user", content: "hi" }],
      tools: [
        { name: "a", description: "", input_schema: { type: "object", properties: {} } },
        { name: "b", description: "", input_schema: { type: "object", properties: {} } },
      ],
    });
    expect((out.tools as any)[1].cache_control).toEqual({ type: "ephemeral" });
    expect((out.tools as any)[0].cache_control).toBeUndefined();
  });

  it("leaves the messages transcript untouched", () => {
    const messages = [{ role: "user" as const, content: "hi" }];
    const out = withPromptCache({ model: "claude-sonnet-4-6", max_tokens: 100, messages });
    expect(out.messages).toEqual(messages);
  });

  it("handles an absent system and absent tools without throwing", () => {
    const out = withPromptCache({
      model: "claude-sonnet-4-6",
      max_tokens: 100,
      messages: [{ role: "user", content: "hi" }],
    });
    expect(out.system).toBeUndefined();
    expect(out.tools).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/llm/__tests__/anthropic-client.test.ts`
Expected: FAIL — `withPromptCache` is not exported.

- [ ] **Step 3: Implement the transform**

Replace the entire contents of `src/llm/anthropic-client.ts` with:

```ts
import Anthropic from "@anthropic-ai/sdk";
import type { LLMClient } from "./llm-client.js";

const EPHEMERAL = { type: "ephemeral" as const };

/**
 * Apply prompt-cache breakpoints to the stable prefix of a request:
 * the system prompt and the tool definitions. The growing `messages`
 * transcript is left uncached. Anthropic caches everything from the
 * start of the prompt up to and including a `cache_control` marker, so
 * one marker on the system block covers tools + system; the marker on
 * the last tool is a defensive second breakpoint for tool-only requests.
 *
 * Note: the cache only engages above the model's minimum cacheable
 * prompt length; short prompts simply go uncached (no error).
 */
export function withPromptCache(
  params: Anthropic.MessageCreateParams
): Anthropic.MessageCreateParams {
  const next: Anthropic.MessageCreateParams = { ...params };

  if (typeof next.system === "string" && next.system.length > 0) {
    next.system = [{ type: "text", text: next.system, cache_control: EPHEMERAL }];
  } else if (Array.isArray(next.system) && next.system.length > 0) {
    const blocks = next.system.map((b) => ({ ...b }));
    blocks[blocks.length - 1] = { ...blocks[blocks.length - 1], cache_control: EPHEMERAL };
    next.system = blocks;
  }

  if (Array.isArray(next.tools) && next.tools.length > 0) {
    const tools = next.tools.map((t) => ({ ...t }));
    tools[tools.length - 1] = { ...tools[tools.length - 1], cache_control: EPHEMERAL };
    next.tools = tools;
  }

  return next;
}

/**
 * Tier-1 provider client. Thin wrapper around @anthropic-ai/sdk that
 * applies prompt caching to every request's stable prefix.
 */
export class AnthropicLLMClient implements LLMClient {
  private readonly inner: Anthropic;

  constructor(opts: { apiKey?: string; baseURL?: string }) {
    this.inner = new Anthropic({ apiKey: opts.apiKey, baseURL: opts.baseURL });
  }

  readonly messages = {
    create: (params: Anthropic.MessageCreateParams): Promise<Anthropic.Message> =>
      this.inner.messages.create(withPromptCache(params)) as Promise<Anthropic.Message>,
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/llm/__tests__/anthropic-client.test.ts`
Expected: PASS (4 tests).

If a `cache_control` type error appears on the tool spread, the installed SDK may type `tools` as a union; cast the mapped array: `next.tools = tools as Anthropic.MessageCreateParams["tools"];`.

- [ ] **Step 5: Typecheck and run the full suite**

Run: `npx tsc --noEmit && npm test`
Expected: clean typecheck, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/llm/anthropic-client.ts src/llm/__tests__/anthropic-client.test.ts
git commit --signoff -m "perf(llm): cache stable prompt prefix on Anthropic client"
```

> **Note on the second client:** `src/agent/providers/anthropic.ts` (`AnthropicProvider`) was reviewed — `createProvider` and `.chat()` have zero callers in `src/`, so it is dead code and is intentionally left untouched. The spec's "only if on a hot path" condition resolves to *skip*.

---

## Task 2: String-aware brace-balanced JSON extractor

**Why:** The four agent parse sites use `text.match(/\{[\s\S]*\}/)`, which grabs from the first `{` to the **last** `}`. Prose containing a `{`, or two JSON objects, breaks it — and the failure is silent. A balanced, string-aware extractor that tries each `{` until one parses fixes this.

**Files:**
- Create: `src/agent/json-extract.ts`
- Test: `src/agent/__tests__/json-extract.test.ts`

- [ ] **Step 1: Write the failing test**

Create `src/agent/__tests__/json-extract.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { extractJson } from "../json-extract.js";

describe("extractJson", () => {
  it("parses a bare JSON object", () => {
    expect(extractJson('{"a":1}')).toEqual({ a: 1 });
  });
  it("parses JSON prefaced by prose", () => {
    expect(extractJson('Here is my answer:\n{"a":1}')).toEqual({ a: 1 });
  });
  it("ignores braces inside string values", () => {
    expect(extractJson('{"a":"text with } brace"}')).toEqual({ a: "text with } brace" });
  });
  it("returns the first valid object when two are present", () => {
    expect(extractJson('{"a":1} {"b":2}')).toEqual({ a: 1 });
  });
  it("skips a prose brace and finds the real object", () => {
    expect(extractJson('note: use {curly} carefully. {"a":1}')).toEqual({ a: 1 });
  });
  it("handles nested objects", () => {
    expect(extractJson('{"a":{"b":{"c":1}}}')).toEqual({ a: { b: { c: 1 } } });
  });
  it("returns null for truncated JSON", () => {
    expect(extractJson('{"a":1, "b":')).toBeNull();
  });
  it("returns null when there is no object", () => {
    expect(extractJson("no json here")).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/agent/__tests__/json-extract.test.ts`
Expected: FAIL — `json-extract` module not found.

- [ ] **Step 3: Implement the extractor**

Create `src/agent/json-extract.ts`:

```ts
/**
 * Extract and parse the first complete, brace-balanced JSON object
 * embedded in `text`. String-aware: braces inside JSON string literals
 * do not affect nesting depth. Each `{` position is tried in turn; the
 * first balanced span that `JSON.parse` accepts is returned, so prose
 * before the object (or a stray `{`) does not break extraction.
 *
 * Returns the parsed value, or `null` if no parseable object is found.
 *
 * Replaces the previous greedy `text.match(/\{[\s\S]*\}/)`, which spanned
 * the first `{` to the LAST `}` and failed on prose braces or >1 object.
 */
export function extractJson<T = unknown>(text: string): T | null {
  for (
    let start = text.indexOf("{");
    start !== -1;
    start = text.indexOf("{", start + 1)
  ) {
    const span = balancedSpan(text, start);
    if (span === null) continue;
    try {
      return JSON.parse(span) as T;
    } catch {
      // This `{` did not begin a valid object; try the next one.
    }
  }
  return null;
}

/**
 * Return the substring from `start` (a `{`) to its matching `}`,
 * ignoring braces inside double-quoted string literals. Returns `null`
 * if the braces never balance before the end of `text`.
 */
function balancedSpan(text: string, start: number): string | null {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/agent/__tests__/json-extract.test.ts`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add src/agent/json-extract.ts src/agent/__tests__/json-extract.test.ts
git commit --signoff -m "feat(agent): add brace-balanced JSON extractor"
```

---

## Task 3: Wire the extractor + warnings into the four parse sites

**Why:** Replace the fragile regex at all four sites and stop discarding model output silently. On parse failure or loop exhaustion, emit a `console.warn` so a degraded run is visible.

> **Scope note (spec deviation):** the spec said "console + a structured field on the returned report." The structured field is trimmed — it would ripple through four report types for little gain. `console.warn` alone satisfies "surface the failure." Flag at plan review if the structured field is wanted.

**Files:**
- Modify: `src/agents/recon-agent.ts`, `src/agents/hypothesis-agent.ts`, `src/agent/analyzer.ts`, `src/agents/exploit-agent.ts`

- [ ] **Step 1: Update `recon-agent.ts`**

Add the import after the existing tool import (line 5):

```ts
import { extractJson } from "../agent/json-extract.js";
```

Replace the `parseRecon` method body (lines 100–117) so it uses `extractJson` and warns on failure:

```ts
  private parseRecon(text: string): ReconReport {
    const data = extractJson<Record<string, unknown>>(text);
    if (data === null) {
      console.warn("[recon] no parseable JSON in model response — using fallback");
      return this.fallbackRecon();
    }
    return {
      type: "recon",
      entryPoints: (data.entryPoints as ReconReport["entryPoints"]) || [],
      techStack: (data.techStack as string[]) || [],
      authBoundaries: (data.authBoundaries as ReconReport["authBoundaries"]) || [],
      dataStores: (data.dataStores as ReconReport["dataStores"]) || [],
      attackSurface: (data.attackSurface as string) || "Unknown",
    };
  }
```

Add an exhaustion warning: in `execute()`, change the final `return this.fallbackRecon();` (currently line 97) to:

```ts
    console.warn("[recon] agent loop exhausted MAX_TURNS without a final answer");
    return this.fallbackRecon();
```

- [ ] **Step 2: Update `hypothesis-agent.ts`**

Add the import after the existing tool import (line 4):

```ts
import { extractJson } from "../agent/json-extract.js";
```

Replace the `parseHypotheses` method body (lines 204–226):

```ts
  private parseHypotheses(text: string): HypothesisReport {
    const data = extractJson<{ hypotheses?: any[] }>(text);
    if (data === null) {
      console.warn("[hypothesis] no parseable JSON in model response — returning none");
      return { type: "hypothesis", hypotheses: [] };
    }
    const hypotheses: SecurityHypothesis[] = (data.hypotheses || []).map(
      (h: any, i: number) => ({
        id: `HYPO-${String(i + 1).padStart(3, "0")}`,
        functionName: h.functionName || "unknown",
        file: h.file || "",
        line: h.line || 0,
        hypothesis: h.hypothesis || "",
        category: h.category || "unknown",
        estimatedSeverity: (h.estimatedSeverity || "medium") as Severity,
        reasoning: h.reasoning || "",
        investigationSteps: h.investigationSteps || [],
      })
    );
    return { type: "hypothesis", hypotheses };
  }
```

Add an exhaustion warning: change the final `return { type: "hypothesis", hypotheses: [] };` after the loop (currently line 181) to:

```ts
    console.warn("[hypothesis] agent loop exhausted MAX_TURNS without a final answer");
    return { type: "hypothesis", hypotheses: [] };
```

- [ ] **Step 3: Update `analyzer.ts`**

Add the import after the tools import (line 5):

```ts
import { extractJson } from "./json-extract.js";
```

In `parseAnalysisResponse` (lines 141–163), replace the regex + `JSON.parse` block:

```ts
export function parseAnalysisResponse(
  text: string,
  phase1Findings: Vulnerability[]
): AnalysisResult {
  const output = extractJson<AIAnalysisOutput>(text);
  if (output === null) {
    console.warn("[analyzer] no parseable JSON in model response — passing phase-1 findings through");
    return { confirmed: phase1Findings, discovered: [], dismissedCount: 0 };
  }
```

Keep the rest of the function (the `confirmed`/`discovered`/`dismissedCount` logic from the existing line 165 onward) unchanged.

Add an exhaustion warning: change the post-loop fallback in `analyze()` (currently lines 109–114) to:

```ts
    console.warn("[analyzer] agent loop exhausted MAX_TURNS — passing phase-1 findings through");
    return {
      confirmed: phase1Findings,
      discovered: [],
      dismissedCount: 0,
    };
```

- [ ] **Step 4: Update `exploit-agent.ts`**

Add the import after the existing imports (line 5):

```ts
import { extractJson } from "../agent/json-extract.js";
```

Replace the `parseExploitReport` method's regex + `JSON.parse` + `try/catch` (lines 105–142). The new body keeps all chain/PoC mapping logic; only the extraction changes:

```ts
  private parseExploitReport(text: string, findings: Vulnerability[]): ExploitReport {
    const data = extractJson<{ chains?: any[]; proofOfConcepts?: any[] }>(text);
    if (data === null) {
      console.warn("[exploit] no parseable JSON in model response — returning empty report");
      return { type: "exploit", chains: [], proofOfConcepts: [] };
    }

    const vulnMap = new Map(findings.map((v) => [v.id, v]));

    const chains: VulnChain[] = (data.chains || [])
      .map((c: any, i: number) => {
        const chainVulns = (c.vulnerabilityIds || [])
          .map((id: string) => vulnMap.get(id))
          .filter(Boolean);
        if (chainVulns.length < 2) return null;
        return {
          id: `CHAIN-${String(i + 1).padStart(3, "0")}`,
          title: c.title,
          severity: c.severity as Severity,
          vulnerabilities: chainVulns,
          narrative: c.narrative,
          impact: c.impact,
        };
      })
      .filter(Boolean) as VulnChain[];

    const proofOfConcepts = (data.proofOfConcepts || []).map((p: any) => ({
      vulnerabilityId: p.vulnerabilityId,
      payload: p.payload || "",
      description: p.description || "",
      verified: false,
    }));

    return { type: "exploit", chains, proofOfConcepts };
  }
```

- [ ] **Step 5: Typecheck and run the full suite**

Run: `npx tsc --noEmit && npm test`
Expected: clean typecheck, all tests pass. `src/agent/__tests__/analyzer.test.ts` pins `parseAnalysisResponse` fallback behavior — it should stay green because `extractJson` returns `null` on no-JSON and on malformed JSON, exactly the conditions the old code fell back on. If a test fails because it asserted the *old* greedy behavior on prose-with-braces, update that test to expect the corrected (now-parsed) result.

- [ ] **Step 6: Commit**

```bash
git add src/agents/recon-agent.ts src/agents/hypothesis-agent.ts src/agent/analyzer.ts src/agents/exploit-agent.ts
git commit --signoff -m "fix(agents): balanced JSON extraction, surface parse and exhaustion failures"
```

---

## Task 4: Combined hunt-tools helper

**Why:** `createAdvancedTools` / `executeAdvancedToolCall` (`src/agent/tools-advanced.ts`) provide call-graph and endpoint tools but are imported by zero hunt agents. A combined helper lets all three agents adopt them with a one-line change each.

**Files:**
- Create: `src/agent/hunt-tools.ts`
- Test: `src/agent/__tests__/hunt-tools.test.ts`

- [ ] **Step 1: Write the failing test**

Create `src/agent/__tests__/hunt-tools.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { createHuntAgentTools } from "../hunt-tools.js";
import { createAgentTools } from "../tools.js";
import { createAdvancedTools } from "../tools-advanced.js";

describe("createHuntAgentTools", () => {
  it("includes every basic tool and every advanced tool", () => {
    const names = new Set(createHuntAgentTools("/tmp/x").map((t) => t.name));
    for (const t of createAgentTools("/tmp/x")) expect(names.has(t.name)).toBe(true);
    for (const t of createAdvancedTools("/tmp/x")) expect(names.has(t.name)).toBe(true);
  });

  it("exposes both a basic tool (read_file) and an advanced tool (list_functions)", () => {
    const names = createHuntAgentTools("/tmp/x").map((t) => t.name);
    expect(names).toContain("read_file");
    expect(names).toContain("list_functions");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/agent/__tests__/hunt-tools.test.ts`
Expected: FAIL — `hunt-tools` module not found.

- [ ] **Step 3: Implement the helper**

Create `src/agent/hunt-tools.ts`:

```ts
import type Anthropic from "@anthropic-ai/sdk";
import { createAgentTools, executeToolCall } from "./tools.js";
import { createAdvancedTools, executeAdvancedToolCall } from "./tools-advanced.js";

// Advanced-tool definitions are static (createAdvancedTools returns a
// fixed array independent of the project path), so the routing name set
// can be computed once at module load.
const ADVANCED_TOOL_NAMES: ReadonlySet<string> = new Set(
  createAdvancedTools("").map((t) => t.name)
);

/**
 * The full toolset for a hunt agent: the four basic grep/read tools
 * plus the advanced call-graph / endpoint tools. Replaces a bare
 * `createAgentTools` call so the recon/hypothesis/analyzer agents can
 * reason across function and file boundaries.
 */
export function createHuntAgentTools(projectPath: string): Anthropic.Tool[] {
  return [...createAgentTools(projectPath), ...createAdvancedTools(projectPath)];
}

/**
 * Dispatch a tool call to the correct executor by tool name: advanced
 * tool names route to `executeAdvancedToolCall`, everything else to the
 * basic `executeToolCall`.
 */
export function executeHuntToolCall(
  projectPath: string,
  toolName: string,
  toolInput: Record<string, unknown>
): Promise<string> {
  if (ADVANCED_TOOL_NAMES.has(toolName)) {
    return executeAdvancedToolCall(projectPath, toolName, toolInput);
  }
  return executeToolCall(projectPath, toolName, toolInput);
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/agent/__tests__/hunt-tools.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/agent/hunt-tools.ts src/agent/__tests__/hunt-tools.test.ts
git commit --signoff -m "feat(agent): add combined hunt toolset helper"
```

---

## Task 5: Wire the combined toolset into the three hunt agents

**Why:** Switch recon, hypothesis, and analyzer from the basic-only toolset to the combined one so the model gains interprocedural reasoning.

**Files:**
- Modify: `src/agents/recon-agent.ts`, `src/agents/hypothesis-agent.ts`, `src/agent/analyzer.ts`

- [ ] **Step 1: Update `recon-agent.ts`**

Change the import (line 5) from:

```ts
import { createAgentTools, executeToolCall } from "../agent/tools.js";
```

to:

```ts
import { createHuntAgentTools, executeHuntToolCall } from "../agent/hunt-tools.js";
```

In `execute()`: change `createAgentTools(this.projectPath)` (line 49) to `createHuntAgentTools(this.projectPath)`, and change `executeToolCall(` (line 74) to `executeHuntToolCall(`.

- [ ] **Step 2: Update `hypothesis-agent.ts`**

Change the import (line 4) from:

```ts
import { createAgentTools, executeToolCall } from "../agent/tools.js";
```

to:

```ts
import { createHuntAgentTools, executeHuntToolCall } from "../agent/hunt-tools.js";
```

Change `createAgentTools(this.projectPath)` (line 96) to `createHuntAgentTools(this.projectPath)`, and `executeToolCall(` (line 158) to `executeHuntToolCall(`.

- [ ] **Step 3: Update `analyzer.ts`**

Change the import (line 5) from:

```ts
import { createAgentTools, executeToolCall } from "./tools.js";
```

to:

```ts
import { createHuntAgentTools, executeHuntToolCall } from "./hunt-tools.js";
```

Change `createAgentTools(projectPath)` (line 57) to `createHuntAgentTools(projectPath)`, and `executeToolCall(` (line 84) to `executeHuntToolCall(`.

- [ ] **Step 4: Typecheck and run the full suite**

Run: `npx tsc --noEmit && npm test`
Expected: clean typecheck, all tests pass. `src/agent/__tests__/analyzer-loop.test.ts` exercises the analyzer loop with a mock client — it does not assert the exact tool list, so it should stay green. If it fails because it asserts a tool count or a specific tool array, update the assertion to expect the combined toolset (`createHuntAgentTools`).

- [ ] **Step 5: Commit**

```bash
git add src/agents/recon-agent.ts src/agents/hypothesis-agent.ts src/agent/analyzer.ts
git commit --signoff -m "feat(agents): wire advanced tools into hunt agent loops"
```

---

## Task 6: Expand the variant seed corpus (+6 seeds)

**Why:** `seed-patterns.ts` has 5 hand-curated seeds → variants v2 can only search for 5 bug shapes. Adding 6 hand-derived seeds roughly doubles distinct-bug-class coverage.

**Nature of this task:** unlike Tasks 1–5, this is *research + data curation*, not code. Each seed is derived by reading a real CVE's fix commit. The procedure, schema, and acceptance test are fully specified below; the per-seed *content* is produced during execution. Work one seed at a time and commit each separately.

**Files:**
- Modify: `src/analysis/root-cause/seed-patterns.ts`
- Create: `src/analysis/root-cause/__tests__/fixtures/<slug>.txt` (one small vulnerable-code fixture per seed)
- Modify or create: `src/analysis/root-cause/__tests__/seed-patterns.test.ts` (seed-count + offline-matcher tests)

**The 6 seeds to add** (bug class · CWE · candidate CVEs — *verify each candidate has a public fix commit before curating; substitute a better-documented CVE in the same class if needed*):

| # | Bug class | CWE | Candidate CVEs to investigate |
|---|-----------|-----|-------------------------------|
| 1 | Prototype pollution | CWE-1321 | CVE-2019-10744 (lodash `defaultsDeep`), CVE-2020-8203 (lodash) |
| 2 | OS command injection | CWE-78 | CVE-2021-21315 (systeminformation), CVE-2022-25912 (simple-git) |
| 3 | Path traversal | CWE-22 | CVE-2021-37713 (tar), CVE-2018-1002204 (adm-zip zip-slip) |
| 4 | Server-side request forgery | CWE-918 | an SSRF advisory in a URL-fetch library — investigate `axios`, `node-fetch`, `request` advisories |
| 5 | SQL injection | CWE-89 | CVE-2019-10752 (sequelize), a `knex`/`mysql` advisory |
| 6 | XML external entity (XXE) | CWE-611 | CVE-2022-39353 (@xmldom/xmldom), a `libxmljs` advisory |

**Per-seed procedure** (repeat for each of the 6):

- [ ] **Step A: Select and verify the CVE.** Pick a CVE for the bug class. Confirm it is JavaScript/TypeScript, has a *public fix commit* you can read, and is well-documented. Read the fix commit and the advisory.

- [ ] **Step B: Derive the `RootCausePattern`.** Open `src/analysis/root-cause/seed-patterns.ts`. The 5 existing seeds in the `SEEDS` array are worked examples of the schema — match their style and depth. Add a new entry with all required fields: `cveId`, `ghsaId`, `bugClass`, `cwe`, `languages`, `astShape` (`{ kind, constraints[] }` — `kind` must be a real tree-sitter node kind such as `call_expression`, `new_expression`, `member_expression`, `function_declaration`, `assignment_expression`, `string`, `template_string`), `dataFlow` (`{ source, sink, propagation }`), and `summary`. Pick the `astShape.kind` that holds the literal text changed by the fix (see the guidance in `src/agent/tools.ts` `KIND_DOC_WORKED_EXAMPLES`). Preserve the file's "hand-derived ground truth — do not regenerate from an LLM" rule (header comment, `seed-patterns.ts:22-25`).

- [ ] **Step C: Write a fixture.** Create `src/analysis/root-cause/__tests__/fixtures/<slug>.txt` (e.g. `prototype-pollution.txt`) containing a small (5–20 line) snippet of vulnerable-shaped code that the seed's `astShape` should match — model it on the real vulnerable code from the fix commit.

- [ ] **Step D: Commit the seed.**
```bash
git add src/analysis/root-cause/seed-patterns.ts src/analysis/root-cause/__tests__/fixtures/<slug>.txt
git commit --signoff -m "feat(variants): add <bug-class> seed pattern (<CVE-ID>)"
```

**After all 6 seeds are added:**

- [ ] **Step E: Add/extend the seed test.** In `src/analysis/root-cause/__tests__/seed-patterns.test.ts`, add (a) an assertion that `SEED_PATTERNS.length === 11`, (b) an assertion that `getSeedPattern(<cveId>)` resolves for each of the 6 new ids, and (c) for each new seed, an offline matcher check: load its fixture and assert `findAstPattern` (from `src/analysis/ast-matcher/index.js`) with the seed's `astShape` returns at least one match. Use the existing `src/analysis/__tests__/variant-analyzer.test.ts` and the A3a offline runner (`src/analysis/calibration/runner.ts`) as references for how `findAstPattern` is called. Example shape:

```ts
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { SEED_PATTERNS, getSeedPattern } from "../seed-patterns.js";
import { findAstPattern } from "../../ast-matcher/index.js";

describe("expanded seed corpus", () => {
  it("has 11 seeds", () => {
    expect(SEED_PATTERNS.length).toBe(11);
  });

  const NEW_IDS = [
    // fill in the 6 CVE ids chosen in Step A
  ];
  for (const id of NEW_IDS) {
    it(`resolves seed ${id}`, () => {
      expect(getSeedPattern(id)).not.toBeNull();
    });
  }
  // Per-seed offline matcher check: load fixtures/<slug>.txt and assert
  // findAstPattern(seed.astShape, fixtureCode, language) returns >= 1 match.
  // Adapt the exact findAstPattern signature from variant-analyzer.test.ts.
});
```

- [ ] **Step F: Run the full suite and typecheck.**

Run: `npx tsc --noEmit && npm test`
Expected: clean. If a pre-existing test asserts `SEED_PATTERNS` count or order (the file header mentions a diff-stable order assertion), update it to include the 6 new seeds.

- [ ] **Step G: Commit the tests.**
```bash
git add src/analysis/root-cause/__tests__/seed-patterns.test.ts
git commit --signoff -m "test(variants): offline matcher checks for the 6 new seeds"
```

> Full agentic calibration of the new seeds (driving the variant-analyzer loop against real vulnerable-commit checkouts, A3b-style) costs API budget and is **deferred** — it happens naturally the first time these seeds are used in a real hunt. The offline matcher check above is the deterministic, zero-cost acceptance gate.

---

## Task 7: Integration verification

**Why:** Confirm the bundle works end to end and the spec's success criteria are met.

**Files:** none modified — verification only.

- [ ] **Step 1: Full typecheck + suite**

Run: `npx tsc --noEmit && npm test`
Expected: clean typecheck, all tests green.

- [ ] **Step 2: Confirm advanced tools reach the hunt agents (no API key needed)**

Run: `npx vitest run src/agent/__tests__/hunt-tools.test.ts`
Confirm `createHuntAgentTools` exposes `list_functions` / `list_endpoints` alongside `read_file`. This proves the wiring path.

- [ ] **Step 3: Live caching + hunt check (requires `ANTHROPIC_API_KEY`; ~a few dollars)**

This step needs API access and is the spec's runtime success criteria. If no key/budget is available, record it as deferred.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export NODE_USE_ENV_PROXY=1   # if behind a proxy
npm run build
node dist/cli/index.js hunt demo-vulnerable-app --json
```

Confirm: (a) the run completes; (b) advanced tools (`list_functions`, call-graph, endpoint tools) appear in the hunt's tool activity; (c) a variants-calibration run (`npm run benchmark:variants-calibration -- --log-turns`) shows `cache_read_input_tokens > 0` on turn ≥2 — if the turn logs do not surface cache fields, add a temporary `console.error(response.usage)` in `AnthropicLLMClient.messages.create` to observe them.

- [ ] **Step 4: Final commit if any fixups were needed**

```bash
git add -A
git commit --signoff -m "chore(tier0): integration fixups"
```

(Skip if there is nothing to commit.)

---

## Self-Review Notes

- **Spec coverage:** Item 1 → Task 1; Item 2 → Tasks 4–5; Item 3 → Task 6; Item 4 → Tasks 2–3. Verification → Task 7. All four spec items covered.
- **Known spec deviations** (flag at plan review): (a) Item 4's "structured field on the returned report" trimmed to `console.warn` only; (b) Item 3's seed validation uses the deterministic offline AST-matcher check instead of full agentic calibration, which is deferred to first real use.
- **Type consistency:** `withPromptCache`, `extractJson`, `createHuntAgentTools`, `executeHuntToolCall` are named identically at definition and every call site.
