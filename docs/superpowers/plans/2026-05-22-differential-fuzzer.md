# Differential URL-Parser Fuzzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a differential fuzzer that runs crafted inputs through three URL parsers and flags security-critical field disagreements, with worker-thread isolation and LLM-assisted triage.

**Architecture:** A new `src/dast/differential-fuzzer/` module — corpus → seeded mutator → per-parser worker-pool execution → pairwise comparison engine → dedup → LLM triage → ranked report. Parser calls run in resource-limited worker threads so a hanging/ReDoS parser becomes a recorded finding instead of crashing the run. A benchmark-style runner drives it.

**Tech Stack:** TypeScript (ESM, `.js` import specifiers), Node 22 `worker_threads`, vitest, `url-parse` (new devDependency), the existing `createLLMClient` factory and `extractJson` helper.

**Spec:** `docs/superpowers/specs/2026-05-22-differential-fuzzer-design.md`

**Repo conventions (apply to every commit):**
- Every commit MUST include a DCO sign-off: `git commit --signoff`. CI fails without the `Signed-off-by:` trailer.
- Commit messages MUST follow Conventional Commits (`type(scope): subject`) — commitlint is enforced.
- `npm test` runs the full vitest suite. Single file: `npx vitest run <path>`. Typecheck: `npx tsc --noEmit`.

---

## File Structure

**Create (all under `src/dast/differential-fuzzer/`):**
- `types.ts` — shared types: `ParserId`, `ParserResult`, `Divergence`, `DivergenceClass`, `TriagedDivergenceClass`, `FuzzReport`.
- `corpus.ts` — hand-curated URL-confusion seed patterns + `loadCorpus()`.
- `mutator.ts` — seeded-RNG mutation: `mutate(seeds, count, seed)`.
- `parsers.ts` — the three parser adapters as a `PARSERS` map.
- `worker.ts` — the worker-thread entry script (runs a parse in the worker).
- `worker-pool.ts` — `WorkerPool` class: per-call timeout, hung-worker replacement.
- `engine.ts` — `compare()` (pairwise divergence detection) + `classify()` (dedup).
- `triage.ts` — `triage()` LLM-assisted divergence categorization.
- `index.ts` — `runDifferentialFuzz()` orchestration.
- `__tests__/` — one test file per logic module.

**Create elsewhere:**
- `benchmarks/differential-fuzz/run.ts` — CLI entry point.

**Modify:**
- `package.json` — add `url-parse` + `@types/url-parse` devDependencies and a `benchmark:differential-fuzz` script.

---

## Task 1: Shared types

**Files:**
- Create: `src/dast/differential-fuzzer/types.ts`

No test — this is a pure type module (verified by `tsc`).

- [ ] **Step 1: Create the types file**

```ts
/** The three URL parsers under differential test. */
export type ParserId = "native-url" | "url-parse" | "legacy-url";

/** Security-relevant URL components compared across parsers. */
export type DivergenceField =
  | "protocol"
  | "hostname"
  | "port"
  | "username"
  | "password"
  | "pathname";

/** Normalized output of one parser for one input. */
export interface ParserResult {
  protocol?: string;
  hostname?: string;
  port?: string;
  username?: string;
  password?: string;
  pathname?: string;
  /** Set when the parser threw on this input. */
  error?: string;
  /** Set when the parse exceeded the worker timeout. */
  hang?: true;
}

export type DivergenceKind = "field" | "throw" | "hang";

/** A single pairwise disagreement on one input. */
export interface Divergence {
  input: string;
  kind: DivergenceKind;
  /** Present when kind === "field". */
  field?: DivergenceField;
  parserA: ParserId;
  parserB: ParserId;
  valueA: string | undefined;
  valueB: string | undefined;
  /** Dedup key — structurally identical divergences share a signature. */
  signature: string;
}

export type TriageCategory = "spec-ambiguity" | "likely-exploitable" | "dos";

/** A deduped group of structurally-identical divergences. */
export interface DivergenceClass {
  signature: string;
  kind: DivergenceKind;
  field?: DivergenceField;
  parserA: ParserId;
  parserB: ParserId;
  /** One representative input from the class. */
  representativeInput: string;
  /** How many fuzzed inputs produced this divergence. */
  count: number;
}

/** A DivergenceClass after LLM triage. */
export interface TriagedDivergenceClass extends DivergenceClass {
  /** Undefined when triage failed for this class. */
  category?: TriageCategory;
  rationale?: string;
}

/** Severity rank of a field — higher sorts first in the report. */
export const FIELD_SEVERITY: Record<DivergenceField, number> = {
  hostname: 5,
  protocol: 5,
  port: 3,
  username: 2,
  password: 2,
  pathname: 1,
};

export interface FuzzReport {
  generatedAt: string;
  seed: number;
  corpusSize: number;
  inputsTested: number;
  classes: TriagedDivergenceClass[];
}
```

- [ ] **Step 2: Typecheck**

Run: `npx tsc --noEmit`
Expected: clean (exit 0).

- [ ] **Step 3: Commit**

```bash
git add src/dast/differential-fuzzer/types.ts
git commit --signoff -m "feat(diff-fuzz): add differential-fuzzer shared types"
```

---

## Task 2: URL-confusion corpus

**Files:**
- Create: `src/dast/differential-fuzzer/corpus.ts`
- Test: `src/dast/differential-fuzzer/__tests__/corpus.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from "vitest";
import { loadCorpus } from "../corpus.js";

describe("loadCorpus", () => {
  it("returns a non-empty corpus", () => {
    expect(loadCorpus().length).toBeGreaterThan(20);
  });

  it("every entry has a non-empty family and url", () => {
    for (const e of loadCorpus()) {
      expect(e.family.length).toBeGreaterThan(0);
      expect(e.url.length).toBeGreaterThan(0);
    }
  });

  it("covers all eight confusion families", () => {
    const families = new Set(loadCorpus().map((e) => e.family));
    for (const f of [
      "embedded-at", "backslash", "missing-slash", "whitespace",
      "unicode-idn", "control-char", "userinfo-port", "ip-oddity",
    ]) {
      expect(families.has(f)).toBe(true);
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/corpus.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Create the corpus**

> IMPORTANT — the code block below may display some `control-char` and `unicode-idn` entries with invisible/stripped bytes. When you write `corpus.ts`, the `control-char` family MUST use explicit escape sequences in the string literals — `\x00`, `\x01`, `\x7f`, `\x0b`, `\x0c` — and the `unicode-idn` whitespace entry MUST use ` `. Concretely, write the `control-char` block as exactly these five distinct entries:
> ```ts
>   // control-char — NUL and other control bytes (escape sequences, not literal bytes)
>   { family: "control-char", url: "http://evil.com\x00.good.com/" },
>   { family: "control-char", url: "http://good.com\x01@evil.com/" },
>   { family: "control-char", url: "http://evil\x7f.com/" },
>   { family: "control-char", url: "http://\x00evil.com/" },
>   { family: "control-char", url: "http://evil.com\x0b\x0c/" },
> ```
> and the last `unicode-idn` entry as `{ family: "unicode-idn", url: "http://evil .com/" }`. Verify no two corpus entries are byte-identical before committing.

```ts
export interface CorpusEntry {
  family: string;
  url: string;
}

/**
 * Hand-curated URL-confusion seed patterns, grouped by family. These are
 * the inputs where real-world URL parsers are known to disagree; the
 * mutator expands them into the full fuzzing input set.
 */
export const CORPUS: CorpusEntry[] = [
  // embedded-at — userinfo "@" confusion (the classic SSRF-bypass family)
  { family: "embedded-at", url: "http://expected.com@evil.com/" },
  { family: "embedded-at", url: "http://expected.com@evil.com@good.com/" },
  { family: "embedded-at", url: "http://user@evil.com:80@good.com/" },
  { family: "embedded-at", url: "http://good.com%2F@evil.com/" },
  { family: "embedded-at", url: "http://good.com#@evil.com/" },
  { family: "embedded-at", url: "http://good.com?@evil.com/" },
  // backslash — backslash treated as slash by some parsers
  { family: "backslash", url: "http://good.com\\@evil.com/" },
  { family: "backslash", url: "http:\\\\evil.com/" },
  { family: "backslash", url: "http://good.com\\.evil.com/" },
  { family: "backslash", url: "https:/\\evil.com/" },
  { family: "backslash", url: "http://evil.com\\good.com/" },
  // missing-slash — scheme without "//"
  { family: "missing-slash", url: "http:evil.com/" },
  { family: "missing-slash", url: "http:/evil.com/" },
  { family: "missing-slash", url: "http:///evil.com/" },
  { family: "missing-slash", url: "https:example.com:8080/" },
  // whitespace — tab / CR / LF inside the URL
  { family: "whitespace", url: "http://good.com\t@evil.com/" },
  { family: "whitespace", url: "http://evil\n.com/" },
  { family: "whitespace", url: "http://evil.com\r/" },
  { family: "whitespace", url: "ht\ttp://evil.com/" },
  { family: "whitespace", url: " http://evil.com/" },
  { family: "whitespace", url: "http://evil.com /" },
  // unicode-idn — unicode, IDN homoglyphs, fullwidth characters
  { family: "unicode-idn", url: "http://evil。com/" },
  { family: "unicode-idn", url: "http://ｅｖｉｌ.com/" },
  { family: "unicode-idn", url: "http://good.com․evil.com/" },
  { family: "unicode-idn", url: "http://xn--80ak6aa92e.com/" },
  { family: "unicode-idn", url: "http://evil.com /" },
  // control-char — NUL and other control bytes
  { family: "control-char", url: "http://evil.com .good.com/" },
  { family: "control-char", url: "http://good.com @evil.com/" },
  { family: "control-char", url: "http://evil.com/" },
  { family: "control-char", url: "http://evil.com/" },
  // userinfo-port — port and userinfo edge cases
  { family: "userinfo-port", url: "http://evil.com:0x50/" },
  { family: "userinfo-port", url: "http://evil.com:+80/" },
  { family: "userinfo-port", url: "http://evil.com:80:80/" },
  { family: "userinfo-port", url: "http://user:pass:extra@evil.com/" },
  { family: "userinfo-port", url: "http://evil.com:/" },
  // ip-oddity — non-canonical IP representations
  { family: "ip-oddity", url: "http://0x7f000001/" },
  { family: "ip-oddity", url: "http://2130706433/" },
  { family: "ip-oddity", url: "http://127.1/" },
  { family: "ip-oddity", url: "http://0177.0.0.1/" },
  { family: "ip-oddity", url: "http://[::ffff:127.0.0.1]/" },
  { family: "ip-oddity", url: "http://127.0.0.1.evil.com/" },
];

export function loadCorpus(): CorpusEntry[] {
  return CORPUS;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/corpus.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/dast/differential-fuzzer/corpus.ts src/dast/differential-fuzzer/__tests__/corpus.test.ts
git commit --signoff -m "feat(diff-fuzz): add URL-confusion seed corpus"
```

---

## Task 3: Seeded mutator

**Files:**
- Create: `src/dast/differential-fuzzer/mutator.ts`
- Test: `src/dast/differential-fuzzer/__tests__/mutator.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from "vitest";
import { mutate } from "../mutator.js";
import type { CorpusEntry } from "../corpus.js";

const SEEDS: CorpusEntry[] = [
  { family: "f", url: "http://a.com/" },
  { family: "f", url: "http://b.com/" },
];

describe("mutate", () => {
  it("is deterministic for a fixed seed", () => {
    expect(mutate(SEEDS, 50, 123)).toEqual(mutate(SEEDS, 50, 123));
  });

  it("produces different output for a different seed", () => {
    expect(mutate(SEEDS, 50, 1)).not.toEqual(mutate(SEEDS, 50, 2));
  });

  it("returns exactly `count` inputs", () => {
    expect(mutate(SEEDS, 30, 7)).toHaveLength(30);
  });

  it("includes the raw seed URLs", () => {
    const out = mutate(SEEDS, 30, 7);
    expect(out).toContain("http://a.com/");
    expect(out).toContain("http://b.com/");
  });

  it("produces mutated inputs beyond the raw seeds", () => {
    const out = mutate(SEEDS, 30, 7);
    const mutated = out.filter((u) => u !== "http://a.com/" && u !== "http://b.com/");
    expect(mutated.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/mutator.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the mutator**

```ts
import type { CorpusEntry } from "./corpus.js";

/** Deterministic PRNG (mulberry32) — a fixed seed yields a fixed sequence. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CONFUSION_CHARS = [
  "@", "\\", "/", "#", "?", ":", "\t", "\n", "\r", " ",
  " ", "。", "．", "%2f", "%00",
];

function flipCase(ch: string): string {
  const lower = ch.toLowerCase();
  return ch === lower ? ch.toUpperCase() : lower;
}

function applyMutation(
  url: string,
  rand: () => number,
  pick: <T>(a: T[]) => T
): string {
  const op = Math.floor(rand() * 5);
  const pos = Math.floor(rand() * (url.length + 1));
  switch (op) {
    case 0: // insert a confusion char
      return url.slice(0, pos) + pick(CONFUSION_CHARS) + url.slice(pos);
    case 1: // duplicate the char at pos
      return pos < url.length ? url.slice(0, pos) + url[pos] + url.slice(pos) : url;
    case 2: // delete the char at pos
      return pos < url.length ? url.slice(0, pos) + url.slice(pos + 1) : url;
    case 3: // flip case at pos
      return pos < url.length
        ? url.slice(0, pos) + flipCase(url[pos]) + url.slice(pos + 1)
        : url;
    default: // append two confusion chars
      return url + pick(CONFUSION_CHARS) + pick(CONFUSION_CHARS);
  }
}

/**
 * Expand the corpus into `count` fuzzing inputs. The raw seed URLs are
 * always included first; the remainder are produced by applying 1-3
 * random mutations to a randomly-picked seed. Fully deterministic given
 * `(seeds, count, seed)`.
 */
export function mutate(seeds: CorpusEntry[], count: number, seed: number): string[] {
  const rand = mulberry32(seed);
  const pick = <T>(arr: T[]): T => arr[Math.floor(rand() * arr.length)];
  const out: string[] = seeds.map((s) => s.url);
  while (out.length < count) {
    let url = pick(seeds).url;
    const ops = 1 + Math.floor(rand() * 3);
    for (let i = 0; i < ops; i++) url = applyMutation(url, rand, pick);
    out.push(url);
  }
  return out.slice(0, count);
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/mutator.test.ts`
Expected: PASS (5 tests). Note: if `count` is smaller than `seeds.length` the raw-seed test could fail — the tests use `count >= seeds.length`, which is the expected usage.

- [ ] **Step 5: Commit**

```bash
git add src/dast/differential-fuzzer/mutator.ts src/dast/differential-fuzzer/__tests__/mutator.test.ts
git commit --signoff -m "feat(diff-fuzz): add seeded URL mutator"
```

---

## Task 4: Parser adapters

**Files:**
- Modify: `package.json` (add `url-parse` + `@types/url-parse` devDependencies)
- Create: `src/dast/differential-fuzzer/parsers.ts`
- Test: `src/dast/differential-fuzzer/__tests__/parsers.test.ts`

- [ ] **Step 1: Install the `url-parse` dependency**

Run: `npm install --save-dev url-parse @types/url-parse`
Expected: `package.json` `devDependencies` gains both entries; `package-lock.json` updates.

- [ ] **Step 2: Write the failing test**

```ts
import { describe, it, expect } from "vitest";
import { PARSERS } from "../parsers.js";

describe("PARSERS", () => {
  it("exposes all three parser ids", () => {
    expect(Object.keys(PARSERS).sort()).toEqual(["legacy-url", "native-url", "url-parse"]);
  });

  it("native-url extracts components from a normal URL", () => {
    const r = PARSERS["native-url"]("http://user:pw@example.com:8080/path");
    expect(r.hostname).toBe("example.com");
    expect(r.protocol).toBe("http:");
    expect(r.port).toBe("8080");
    expect(r.username).toBe("user");
    expect(r.error).toBeUndefined();
  });

  it("native-url returns an error result (no throw) on a malformed input", () => {
    const r = PARSERS["native-url"]("not a url");
    expect(r.error).toBeDefined();
    expect(r.hostname).toBeUndefined();
  });

  it("url-parse extracts a hostname", () => {
    expect(PARSERS["url-parse"]("http://example.com/path").hostname).toBe("example.com");
  });

  it("legacy-url extracts a hostname and splits auth into username/password", () => {
    const r = PARSERS["legacy-url"]("http://user:pw@example.com/path");
    expect(r.hostname).toBe("example.com");
    expect(r.username).toBe("user");
    expect(r.password).toBe("pw");
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/parsers.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement the adapters**

First confirm the `url-parse` call shape: it is a default-exported callable, `urlParse(input)`, returning an object with `.protocol`, `.hostname`, `.port`, `.username`, `.password`, `.pathname`. Then create `src/dast/differential-fuzzer/parsers.ts`:

```ts
import { parse as legacyParse } from "node:url";
import urlParse from "url-parse";
import type { ParserId, ParserResult } from "./types.js";

/** WHATWG `URL` — the spec reference. */
function nativeUrl(input: string): ParserResult {
  try {
    const u = new URL(input);
    return {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port,
      username: u.username,
      password: u.password,
      pathname: u.pathname,
    };
  } catch (e) {
    return { error: String(e) };
  }
}

/** The `url-parse` npm package — deliberately lenient. */
function urlParseAdapter(input: string): ParserResult {
  try {
    const u = urlParse(input);
    return {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port,
      username: u.username,
      password: u.password,
      pathname: u.pathname,
    };
  } catch (e) {
    return { error: String(e) };
  }
}

/** Node's legacy `url.parse` — deprecated but still widely used. */
function legacyUrl(input: string): ParserResult {
  try {
    const u = legacyParse(input);
    let username: string | undefined;
    let password: string | undefined;
    if (u.auth) {
      const idx = u.auth.indexOf(":");
      username = idx >= 0 ? u.auth.slice(0, idx) : u.auth;
      password = idx >= 0 ? u.auth.slice(idx + 1) : undefined;
    }
    return {
      protocol: u.protocol ?? undefined,
      hostname: u.hostname ?? undefined,
      port: u.port ?? undefined,
      username,
      password,
      pathname: u.pathname ?? undefined,
    };
  } catch (e) {
    return { error: String(e) };
  }
}

/** The three URL parsers under differential test, keyed by id. */
export const PARSERS: Record<ParserId, (input: string) => ParserResult> = {
  "native-url": nativeUrl,
  "url-parse": urlParseAdapter,
  "legacy-url": legacyUrl,
};
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/parsers.test.ts`
Expected: PASS (5 tests). If the `url-parse` import shape differs (e.g. it needs `urlParse.default` under this module setup), adjust the import and re-run — do not change the test.

- [ ] **Step 6: Typecheck + commit**

Run: `npx tsc --noEmit` (expect clean).

```bash
git add package.json package-lock.json src/dast/differential-fuzzer/parsers.ts src/dast/differential-fuzzer/__tests__/parsers.test.ts
git commit --signoff -m "feat(diff-fuzz): add the three URL parser adapters"
```

---

## Task 5: Worker thread + worker pool

**Files:**
- Create: `src/dast/differential-fuzzer/worker.ts`
- Create: `src/dast/differential-fuzzer/worker-pool.ts`
- Test: `src/dast/differential-fuzzer/__tests__/worker-pool.test.ts`

The worker pool's timeout/replacement logic is tested with injected fake workers (no real `worker_threads` in the unit test — vitest cannot load a `.ts` worker file directly). The real worker round-trip is exercised by the Task 10 offline run against the built output.

- [ ] **Step 1: Create the worker entry script**

`src/dast/differential-fuzzer/worker.ts`:

```ts
import { parentPort } from "node:worker_threads";
import { PARSERS } from "./parsers.js";
import type { ParserId } from "./types.js";

// This module is loaded both as a worker entry point (parentPort set) and
// — harmlessly — when bundlers walk imports. The handler only registers
// when actually running inside a worker.
if (parentPort) {
  parentPort.on("message", (msg: { parserId: string; input: string }) => {
    // Deliberate test hook: lets the worker-pool timeout path be exercised
    // against a guaranteed hang without depending on a real ReDoS input.
    if (msg.parserId === "__hang__") {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        /* intentional infinite loop — the pool terminates this worker */
      }
    }
    const parser = PARSERS[msg.parserId as ParserId];
    parentPort!.postMessage(
      parser ? parser(msg.input) : { error: `unknown parser: ${msg.parserId}` }
    );
  });
}
```

- [ ] **Step 2: Write the failing test for the pool**

`src/dast/differential-fuzzer/__tests__/worker-pool.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { WorkerPool, type WorkerLike } from "../worker-pool.js";
import type { ParserResult } from "../types.js";

/** A fake worker that simulates one of three behaviors. */
function fakeWorker(behavior: "ok" | "hang" | "error"): WorkerLike {
  let onMessage: ((v: ParserResult) => void) | undefined;
  let onError: ((e: unknown) => void) | undefined;
  return {
    postMessage() {
      if (behavior === "ok") setTimeout(() => onMessage?.({ hostname: "ok.com" }), 0);
      else if (behavior === "error") setTimeout(() => onError?.(new Error("boom")), 0);
      // "hang": never responds
    },
    once(event: "message" | "error", cb: (v: never) => void) {
      if (event === "message") onMessage = cb as (v: ParserResult) => void;
      else onError = cb as (e: unknown) => void;
    },
    removeAllListeners() {
      onMessage = undefined;
      onError = undefined;
    },
    terminate() {},
  };
}

describe("WorkerPool", () => {
  it("resolves with the parser result on a normal response", async () => {
    const pool = new WorkerPool({ size: 1, spawn: () => fakeWorker("ok") });
    const r = await pool.runParse("native-url", "http://x");
    expect(r).toEqual({ hostname: "ok.com" });
    await pool.destroy();
  });

  it("resolves with { hang: true } when a parse exceeds the timeout", async () => {
    const pool = new WorkerPool({ size: 1, timeoutMs: 20, spawn: () => fakeWorker("hang") });
    const r = await pool.runParse("native-url", "http://x");
    expect(r).toEqual({ hang: true });
    await pool.destroy();
  });

  it("resolves with an error result when the worker errors", async () => {
    const pool = new WorkerPool({ size: 1, spawn: () => fakeWorker("error") });
    const r = await pool.runParse("native-url", "http://x");
    expect(r.error).toContain("boom");
    await pool.destroy();
  });

  it("keeps serving calls after a hang (worker was replaced)", async () => {
    let behavior: "hang" | "ok" = "hang";
    const pool = new WorkerPool({
      size: 1,
      timeoutMs: 20,
      spawn: () => fakeWorker(behavior),
    });
    expect(await pool.runParse("native-url", "a")).toEqual({ hang: true });
    behavior = "ok"; // the replacement worker behaves normally
    expect(await pool.runParse("native-url", "b")).toEqual({ hostname: "ok.com" });
    await pool.destroy();
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/worker-pool.test.ts`
Expected: FAIL — `worker-pool` module not found.

- [ ] **Step 4: Implement the worker pool**

`src/dast/differential-fuzzer/worker-pool.ts`:

```ts
import { Worker } from "node:worker_threads";
import type { ParserId, ParserResult } from "./types.js";

/** The minimal worker surface the pool depends on — lets tests inject fakes. */
export interface WorkerLike {
  postMessage(value: unknown): void;
  once(event: "message", cb: (value: ParserResult) => void): void;
  once(event: "error", cb: (err: unknown) => void): void;
  removeAllListeners(): void;
  terminate(): void;
}

// Resolved relative to THIS module so it works in both the dist/ and
// dist-benchmarks/ compiled layouts (the worker .js is always a sibling).
const WORKER_PATH = new URL("./worker.js", import.meta.url);

function spawnRealWorker(): WorkerLike {
  return new Worker(WORKER_PATH) as unknown as WorkerLike;
}

export interface WorkerPoolOptions {
  size?: number;
  timeoutMs?: number;
  /** Override worker creation — used by tests to inject fakes. */
  spawn?: () => WorkerLike;
}

/**
 * A small pool of persistent workers. Each `runParse` call races the
 * worker's response against a per-call timeout; on timeout the worker is
 * terminated (it hung) and replaced, and the call resolves `{ hang: true }`.
 */
export class WorkerPool {
  private readonly spawn: () => WorkerLike;
  private readonly timeoutMs: number;
  private readonly available: WorkerLike[];

  constructor(opts: WorkerPoolOptions = {}) {
    this.spawn = opts.spawn ?? spawnRealWorker;
    this.timeoutMs = opts.timeoutMs ?? 1000;
    this.available = Array.from({ length: opts.size ?? 4 }, () => this.spawn());
  }

  runParse(parserId: ParserId | "__hang__", input: string): Promise<ParserResult> {
    const worker = this.available.pop() ?? this.spawn();
    return new Promise<ParserResult>((resolve) => {
      const finish = (result: ParserResult, dead: boolean) => {
        clearTimeout(timer);
        worker.removeAllListeners();
        if (dead) {
          worker.terminate();
          this.available.push(this.spawn());
        } else {
          this.available.push(worker);
        }
        resolve(result);
      };
      const timer = setTimeout(() => finish({ hang: true }, true), this.timeoutMs);
      worker.once("message", (result) => finish(result, false));
      worker.once("error", (err) => finish({ error: String(err) }, true));
      worker.postMessage({ parserId, input });
    });
  }

  async destroy(): Promise<void> {
    for (const w of this.available) w.terminate();
    this.available.length = 0;
  }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/worker-pool.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 6: Typecheck + commit**

Run: `npx tsc --noEmit` (expect clean).

```bash
git add src/dast/differential-fuzzer/worker.ts src/dast/differential-fuzzer/worker-pool.ts src/dast/differential-fuzzer/__tests__/worker-pool.test.ts
git commit --signoff -m "feat(diff-fuzz): add worker-thread parser isolation pool"
```

---

## Task 6: Comparison engine

**Files:**
- Create: `src/dast/differential-fuzzer/engine.ts`
- Test: `src/dast/differential-fuzzer/__tests__/engine.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from "vitest";
import { compare, classify } from "../engine.js";
import type { ParserId, ParserResult } from "../types.js";

function results(over: Partial<Record<ParserId, ParserResult>>): Record<ParserId, ParserResult> {
  const base: ParserResult = { hostname: "same.com", protocol: "http:" };
  return {
    "native-url": { ...base, ...over["native-url"] },
    "url-parse": { ...base, ...over["url-parse"] },
    "legacy-url": { ...base, ...over["legacy-url"] },
  };
}

describe("compare", () => {
  it("emits no divergence when all parsers agree", () => {
    expect(compare("http://x", results({}))).toEqual([]);
  });

  it("emits a field divergence when two parsers disagree on hostname", () => {
    const d = compare("http://x", results({ "url-parse": { hostname: "evil.com" } }));
    const host = d.filter((x) => x.kind === "field" && x.field === "hostname");
    expect(host.length).toBeGreaterThan(0);
    expect(host[0].valueA === "evil.com" || host[0].valueB === "evil.com").toBe(true);
  });

  it("emits a hang divergence when one parser hung and another did not", () => {
    const d = compare("http://x", results({ "legacy-url": { hang: true } }));
    expect(d.some((x) => x.kind === "hang")).toBe(true);
  });

  it("emits a throw divergence when one parser threw and another did not", () => {
    const d = compare("http://x", results({ "legacy-url": { error: "bad" } }));
    expect(d.some((x) => x.kind === "throw")).toBe(true);
  });
});

describe("classify", () => {
  it("collapses structurally identical divergences into one class with a count", () => {
    const a = compare("http://1", results({ "url-parse": { hostname: "aaa.aaa" } }));
    const b = compare("http://2", results({ "url-parse": { hostname: "bbb.bbb" } }));
    const classes = classify([...a, ...b]);
    const hostClass = classes.find((c) => c.field === "hostname");
    expect(hostClass).toBeDefined();
    expect(hostClass!.count).toBe(2);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/engine.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the engine**

```ts
import type {
  ParserId,
  ParserResult,
  Divergence,
  DivergenceClass,
  DivergenceField,
} from "./types.js";

const PARSER_IDS: ParserId[] = ["native-url", "url-parse", "legacy-url"];
const FIELDS: DivergenceField[] = [
  "protocol", "hostname", "port", "username", "password", "pathname",
];

/**
 * Structural skeleton of a value: letters/digits collapsed to placeholders,
 * special characters kept. Two values with the same skeleton are treated as
 * the same *kind* of divergence for dedup. `undefined` → the sentinel "∅".
 */
function skeleton(v: string | undefined): string {
  if (v === undefined) return "∅";
  return v
    .replace(/[a-z]/g, "a")
    .replace(/[A-Z]/g, "A")
    .replace(/[0-9]/g, "0");
}

function mkDivergence(
  input: string,
  kind: Divergence["kind"],
  field: DivergenceField | undefined,
  a: ParserId,
  b: ParserId,
  va: string | undefined,
  vb: string | undefined
): Divergence {
  const signature = `${kind}:${field ?? "-"}:${a}|${b}:${skeleton(va)}|${skeleton(vb)}`;
  return { input, kind, field, parserA: a, parserB: b, valueA: va, valueB: vb, signature };
}

/** Compare every parser pair for one input; emit pairwise divergences. */
export function compare(
  input: string,
  results: Record<ParserId, ParserResult>
): Divergence[] {
  const out: Divergence[] = [];
  for (let i = 0; i < PARSER_IDS.length; i++) {
    for (let j = i + 1; j < PARSER_IDS.length; j++) {
      const a = PARSER_IDS[i];
      const b = PARSER_IDS[j];
      const ra = results[a];
      const rb = results[b];

      // hang divergence — one hung, the other did not
      if (Boolean(ra.hang) !== Boolean(rb.hang)) {
        out.push(mkDivergence(input, "hang", undefined, a, b,
          ra.hang ? "hang" : "ok", rb.hang ? "hang" : "ok"));
        continue;
      }
      if (ra.hang && rb.hang) continue;

      // throw divergence — one threw, the other did not
      const aThrew = ra.error !== undefined;
      const bThrew = rb.error !== undefined;
      if (aThrew !== bThrew) {
        out.push(mkDivergence(input, "throw", undefined, a, b,
          aThrew ? "throw" : "ok", bThrew ? "throw" : "ok"));
        continue;
      }
      if (aThrew && bThrew) continue;

      // field divergences
      for (const field of FIELDS) {
        if (ra[field] !== rb[field]) {
          out.push(mkDivergence(input, "field", field, a, b, ra[field], rb[field]));
        }
      }
    }
  }
  return out;
}

/** Deduplicate divergences by signature into counted classes. */
export function classify(divergences: Divergence[]): DivergenceClass[] {
  const map = new Map<string, DivergenceClass>();
  for (const d of divergences) {
    const existing = map.get(d.signature);
    if (existing) {
      existing.count++;
    } else {
      map.set(d.signature, {
        signature: d.signature,
        kind: d.kind,
        field: d.field,
        parserA: d.parserA,
        parserB: d.parserB,
        representativeInput: d.input,
        count: 1,
      });
    }
  }
  return [...map.values()];
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/engine.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/dast/differential-fuzzer/engine.ts src/dast/differential-fuzzer/__tests__/engine.test.ts
git commit --signoff -m "feat(diff-fuzz): add divergence comparison engine"
```

---

## Task 7: LLM-assisted triage

**Files:**
- Create: `src/dast/differential-fuzzer/triage.ts`
- Test: `src/dast/differential-fuzzer/__tests__/triage.test.ts`

The triage module reuses two existing pieces: the `LLMClient` interface / `createLLMClient` factory in `src/llm/index.js`, and the `extractJson` helper in `src/agent/json-extract.js` (added in the Tier 0 work). Read `src/agent/analyzer.ts` for the established agentic call pattern (`client.messages.create({ model, max_tokens, system, messages })`).

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect, vi } from "vitest";
import { triage } from "../triage.js";
import type { DivergenceClass } from "../types.js";
import type { LLMClient } from "../../../llm/index.js";

const CLASS: DivergenceClass = {
  signature: "field:hostname:native-url|url-parse:a.a|A.a",
  kind: "field",
  field: "hostname",
  parserA: "native-url",
  parserB: "url-parse",
  representativeInput: "http://good.com@evil.com/",
  count: 3,
};

function mockClient(text: string): LLMClient {
  return {
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [{ type: "text", text }],
        stop_reason: "end_turn",
      }),
    },
  } as unknown as LLMClient;
}

describe("triage", () => {
  it("attaches the LLM category and rationale to each class", async () => {
    const client = mockClient(
      '{"category":"likely-exploitable","rationale":"hostname disagreement enables SSRF bypass"}'
    );
    const out = await triage([CLASS], client, "claude-sonnet-4-6");
    expect(out[0].category).toBe("likely-exploitable");
    expect(out[0].rationale).toContain("SSRF");
  });

  it("returns the class un-triaged (no category) when the LLM call throws", async () => {
    const client = {
      messages: { create: vi.fn().mockRejectedValue(new Error("network")) },
    } as unknown as LLMClient;
    const out = await triage([CLASS], client, "claude-sonnet-4-6");
    expect(out[0].category).toBeUndefined();
    expect(out[0].signature).toBe(CLASS.signature);
  });

  it("returns the class un-triaged when the LLM returns unparseable output", async () => {
    const out = await triage([CLASS], mockClient("no json here"), "claude-sonnet-4-6");
    expect(out[0].category).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/triage.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement triage**

```ts
import type { LLMClient } from "../../llm/index.js";
import { extractJson } from "../../agent/json-extract.js";
import type {
  DivergenceClass,
  TriagedDivergenceClass,
  TriageCategory,
} from "./types.js";

const TRIAGE_SYSTEM = `You are a security analyst triaging URL-parser differential-fuzzing results.

Two URL parsers disagreed about how to parse the same input. Most disagreements are harmless spec-ambiguity. Some are real security bugs: when two parsers in one request path disagree about a URL's hostname/protocol/port, an attacker can make a security check see one host while the HTTP client connects to another (SSRF filter bypass, open redirect, auth bypass).

Categorize the divergence as exactly one of:
- "spec-ambiguity": both behaviors are defensible; not a security bug.
- "likely-exploitable": the disagreement could enable SSRF, open-redirect, or auth-bypass.
- "dos": one parser hung or crashed — a resource-exhaustion finding.

Output ONLY a JSON object: {"category": "<one of the three>", "rationale": "<one sentence>"}`;

function isCategory(v: unknown): v is TriageCategory {
  return v === "spec-ambiguity" || v === "likely-exploitable" || v === "dos";
}

async function triageOne(
  cls: DivergenceClass,
  client: LLMClient,
  model: string
): Promise<TriagedDivergenceClass> {
  const prompt = `Divergence kind: ${cls.kind}${cls.field ? ` (field: ${cls.field})` : ""}
Parsers that disagreed: ${cls.parserA} vs ${cls.parserB}
Representative input: ${JSON.stringify(cls.representativeInput)}
This divergence occurred on ${cls.count} fuzzed input(s).

Categorize this divergence.`;

  const response = await client.messages.create({
    model,
    max_tokens: 512,
    system: TRIAGE_SYSTEM,
    messages: [{ role: "user", content: prompt }],
  });

  const textBlock = response.content.find((b) => b.type === "text");
  const text = textBlock && textBlock.type === "text" ? textBlock.text : "";
  const parsed = extractJson<{ category?: unknown; rationale?: unknown }>(text);

  if (parsed && isCategory(parsed.category)) {
    return {
      ...cls,
      category: parsed.category,
      rationale: typeof parsed.rationale === "string" ? parsed.rationale : undefined,
    };
  }
  console.warn(`[diff-fuzz] triage: unparseable LLM output for ${cls.signature}`);
  return { ...cls };
}

/**
 * Run LLM-assisted triage over each divergence class. A class whose triage
 * call fails or returns unparseable output is returned un-triaged (no
 * `category`) with a warning — the run still completes.
 */
export async function triage(
  classes: DivergenceClass[],
  client: LLMClient,
  model: string
): Promise<TriagedDivergenceClass[]> {
  const out: TriagedDivergenceClass[] = [];
  for (const cls of classes) {
    try {
      out.push(await triageOne(cls, client, model));
    } catch (e) {
      console.warn(`[diff-fuzz] triage failed for ${cls.signature}: ${String(e)}`);
      out.push({ ...cls });
    }
  }
  return out;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/triage.test.ts`
Expected: PASS (3 tests). If the `LLMClient` import path or the `messages.create` response shape differs from what the test mock assumes, read `src/llm/index.ts` and `src/llm/llm-client.ts` and align the test mock + implementation to the real interface — keep the three test scenarios (success, throw, unparseable) intact.

- [ ] **Step 5: Typecheck + commit**

Run: `npx tsc --noEmit` (expect clean).

```bash
git add src/dast/differential-fuzzer/triage.ts src/dast/differential-fuzzer/__tests__/triage.test.ts
git commit --signoff -m "feat(diff-fuzz): add LLM-assisted divergence triage"
```

---

## Task 8: Orchestrator

**Files:**
- Create: `src/dast/differential-fuzzer/index.ts`
- Test: `src/dast/differential-fuzzer/__tests__/index.test.ts`

The orchestrator wires every prior piece together. Its test injects a fake worker pool (via the `spawn` option) and a mock LLM client so it runs offline with no real `worker_threads` and no API cost.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect, vi } from "vitest";
import { runDifferentialFuzz } from "../index.js";
import type { WorkerLike } from "../worker-pool.js";
import { PARSERS } from "../parsers.js";
import type { LLMClient } from "../../../llm/index.js";

// A fake worker that runs the real parsers in-process (no worker_threads).
function inProcessWorker(): WorkerLike {
  let onMessage: ((v: unknown) => void) | undefined;
  return {
    postMessage(value: unknown) {
      const { parserId, input } = value as { parserId: string; input: string };
      const parser = PARSERS[parserId as keyof typeof PARSERS];
      const result = parser ? parser(input) : { error: "unknown" };
      setTimeout(() => onMessage?.(result), 0);
    },
    once(event: "message" | "error", cb: (v: never) => void) {
      if (event === "message") onMessage = cb as (v: unknown) => void;
    },
    removeAllListeners() {
      onMessage = undefined;
    },
    terminate() {},
  };
}

function mockClient(): LLMClient {
  return {
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [{ type: "text", text: '{"category":"spec-ambiguity","rationale":"ok"}' }],
        stop_reason: "end_turn",
      }),
    },
  } as unknown as LLMClient;
}

describe("runDifferentialFuzz", () => {
  it("produces a well-formed report over a small run", async () => {
    const report = await runDifferentialFuzz({
      count: 40,
      seed: 99,
      model: "claude-sonnet-4-6",
      client: mockClient(),
      spawnWorker: inProcessWorker,
    });
    expect(report.inputsTested).toBe(40);
    expect(report.seed).toBe(99);
    expect(report.corpusSize).toBeGreaterThan(0);
    expect(Array.isArray(report.classes)).toBe(true);
    expect(typeof report.generatedAt).toBe("string");
    // URL parsers are well known to diverge — a 40-input run must find some.
    expect(report.classes.length).toBeGreaterThan(0);
  });

  it("ranks likely-exploitable classes above spec-ambiguity", async () => {
    const report = await runDifferentialFuzz({
      count: 60,
      seed: 5,
      model: "claude-sonnet-4-6",
      client: mockClient(),
      spawnWorker: inProcessWorker,
    });
    const cats = report.classes.map((c) => c.category);
    const firstAmbiguity = cats.indexOf("spec-ambiguity");
    const lastExploit = cats.lastIndexOf("likely-exploitable");
    if (firstAmbiguity !== -1 && lastExploit !== -1) {
      expect(lastExploit).toBeLessThan(firstAmbiguity);
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/index.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the orchestrator**

```ts
import type { LLMClient } from "../../llm/index.js";
import { loadCorpus } from "./corpus.js";
import { mutate } from "./mutator.js";
import { WorkerPool, type WorkerLike } from "./worker-pool.js";
import { compare, classify } from "./engine.js";
import { triage } from "./triage.js";
import {
  FIELD_SEVERITY,
  type Divergence,
  type ParserId,
  type ParserResult,
  type TriagedDivergenceClass,
  type FuzzReport,
} from "./types.js";

export interface DifferentialFuzzOptions {
  /** Number of fuzzing inputs to generate. */
  count: number;
  /** RNG seed — fixes the input set for reproducibility. */
  seed: number;
  /** Model id for the triage LLM calls. */
  model: string;
  /** LLM client for triage. */
  client: LLMClient;
  /** Worker pool size. Default 4. */
  poolSize?: number;
  /** Per-parse timeout in ms. Default 1000. */
  timeoutMs?: number;
  /** Override worker creation — used by tests to avoid real worker_threads. */
  spawnWorker?: () => WorkerLike;
}

const CATEGORY_RANK: Record<string, number> = {
  "likely-exploitable": 3,
  dos: 2,
  "spec-ambiguity": 1,
};

/** Sort comparator: exploitable first, then by field severity, then by count. */
function rankClasses(a: TriagedDivergenceClass, b: TriagedDivergenceClass): number {
  const ca = CATEGORY_RANK[a.category ?? ""] ?? 0;
  const cb = CATEGORY_RANK[b.category ?? ""] ?? 0;
  if (ca !== cb) return cb - ca;
  const fa = a.field ? FIELD_SEVERITY[a.field] : 0;
  const fb = b.field ? FIELD_SEVERITY[b.field] : 0;
  if (fa !== fb) return fb - fa;
  return b.count - a.count;
}

/**
 * Run the differential URL-parser fuzzer end to end: load the corpus,
 * mutate it into `count` inputs, parse each through all three parsers in
 * worker-isolated calls, compare, dedup, LLM-triage, and rank.
 */
export async function runDifferentialFuzz(
  opts: DifferentialFuzzOptions
): Promise<FuzzReport> {
  const corpus = loadCorpus();
  const inputs = mutate(corpus, opts.count, opts.seed);

  const pool = new WorkerPool({
    size: opts.poolSize,
    timeoutMs: opts.timeoutMs,
    spawn: opts.spawnWorker,
  });

  const divergences: Divergence[] = [];
  try {
    for (const input of inputs) {
      const ids: ParserId[] = ["native-url", "url-parse", "legacy-url"];
      const parsed = await Promise.all(ids.map((id) => pool.runParse(id, input)));
      const results: Record<ParserId, ParserResult> = {
        "native-url": parsed[0],
        "url-parse": parsed[1],
        "legacy-url": parsed[2],
      };
      divergences.push(...compare(input, results));
    }
  } finally {
    await pool.destroy();
  }

  const classes = classify(divergences);
  const triaged = await triage(classes, opts.client, opts.model);
  triaged.sort(rankClasses);

  return {
    generatedAt: new Date().toISOString(),
    seed: opts.seed,
    corpusSize: corpus.length,
    inputsTested: inputs.length,
    classes: triaged,
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/dast/differential-fuzzer/__tests__/index.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Typecheck + full suite + commit**

Run: `npx tsc --noEmit && npm test` (expect clean typecheck, all tests pass).

```bash
git add src/dast/differential-fuzzer/index.ts src/dast/differential-fuzzer/__tests__/index.test.ts
git commit --signoff -m "feat(diff-fuzz): add differential-fuzz orchestrator"
```

---

## Task 9: Benchmark runner

**Files:**
- Create: `benchmarks/differential-fuzz/run.ts`
- Modify: `package.json` (add the `benchmark:differential-fuzz` script)

First read `benchmarks/variants-calibration/run.ts` and the `benchmark:variants-calibration` entry in `package.json` — mirror their structure (arg parsing, the `tsc -p tsconfig.benchmarks.json && node dist-benchmarks/...` script form, how they build a `MythosConfig` / LLM client). Confirm `tsconfig.benchmarks.json` compiles `src/` too (it must, since variants-calibration imports from `src/`).

- [ ] **Step 1: Add the npm script**

In `package.json` `scripts`, add (next to `benchmark:variants-calibration`):

```json
"benchmark:differential-fuzz": "tsc -p tsconfig.benchmarks.json && node dist-benchmarks/benchmarks/differential-fuzz/run.js"
```

- [ ] **Step 2: Create the runner**

`benchmarks/differential-fuzz/run.ts`. Use the same config/client-construction approach as `benchmarks/variants-calibration/run.ts` (it already resolves `ANTHROPIC_API_KEY`, provider, and model). The runner parses `--count`, `--seed`, `--results-subdir`, runs the fuzzer, prints a summary, and writes the JSON report.

```ts
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createLLMClient } from "../../src/llm/index.js";
import { loadConfig } from "../../src/config/config.js";
import { runDifferentialFuzz } from "../../src/dast/differential-fuzzer/index.js";

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

async function main(): Promise<void> {
  const count = Number(arg("count", "2000"));
  const seed = Number(arg("seed", "1"));
  const subdir = arg("results-subdir", new Date().toISOString().replace(/[:.]/g, "-"));

  const config = loadConfig(process.cwd());
  if (!config.apiKey) {
    console.error("differential-fuzz: API key required for triage. Configure ANTHROPIC_API_KEY.");
    process.exit(1);
  }
  const client = createLLMClient(config);

  console.log(`differential-fuzz: count=${count} seed=${seed}`);
  const report = await runDifferentialFuzz({ count, seed, model: config.model, client });

  const outDir = join("benchmarks", "differential-fuzz", "results", subdir);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2));

  const exploit = report.classes.filter((c) => c.category === "likely-exploitable").length;
  const dos = report.classes.filter((c) => c.category === "dos").length;
  console.log("\ndifferential-fuzz scoreboard");
  console.log("=".repeat(60));
  console.log(`  inputs tested:        ${report.inputsTested}`);
  console.log(`  divergence classes:   ${report.classes.length}`);
  console.log(`  likely-exploitable:   ${exploit}`);
  console.log(`  dos:                  ${dos}`);
  console.log("-".repeat(60));
  console.log(`  report → ${join(outDir, "report.json")}`);
  for (const c of report.classes.slice(0, 10)) {
    console.log(`  [${c.category ?? "untriaged"}] ${c.kind}/${c.field ?? "-"} ` +
      `${c.parserA} vs ${c.parserB} ×${c.count}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
```

If `loadConfig` or `createLLMClient` import paths differ from the variants-calibration runner, copy that runner's exact imports.

- [ ] **Step 3: Verify the runner compiles**

Run: `npx tsc -p tsconfig.benchmarks.json`
Expected: clean (exit 0). This compiles the runner and its `src/` imports into `dist-benchmarks/`.

- [ ] **Step 4: Commit**

```bash
git add package.json benchmarks/differential-fuzz/run.ts
git commit --signoff -m "feat(diff-fuzz): add benchmark runner for the differential fuzzer"
```

---

## Task 10: Integration verification

**Files:** none modified — verification only.

- [ ] **Step 1: Full typecheck + suite**

Run: `npx tsc --noEmit && npm test`
Expected: clean typecheck; all tests green (the prior tasks added corpus, mutator, parsers, worker-pool, engine, triage, and orchestrator test files).

- [ ] **Step 2: Real worker round-trip (offline, no API key needed)**

The unit tests inject fake workers; this step exercises the REAL `worker_threads` path. Build the benchmark output and run a tiny offline check:

Run: `npx tsc -p tsconfig.benchmarks.json`

Then run this one-off script to confirm the real worker pool parses and the `__hang__` test hook is caught:

```bash
node --input-type=module -e "
import { WorkerPool } from './dist-benchmarks/src/dast/differential-fuzzer/worker-pool.js';
const pool = new WorkerPool({ size: 2, timeoutMs: 500 });
const ok = await pool.runParse('native-url', 'http://user@example.com:8080/p');
const hang = await pool.runParse('__hang__', 'x');
await pool.destroy();
console.log('real-worker ok:', JSON.stringify(ok));
console.log('real-worker hang:', JSON.stringify(hang));
if (ok.hostname !== 'example.com') { console.error('FAIL: expected hostname example.com'); process.exit(1); }
if (hang.hang !== true) { console.error('FAIL: expected hang result'); process.exit(1); }
console.log('PASS: real worker pool parses and survives a hang');
"
```

Expected: `real-worker ok` shows `hostname:"example.com"`; `real-worker hang` shows `{"hang":true}`; final line `PASS`. If the `dist-benchmarks` path to `worker-pool.js` differs, adjust it to the actual compiled location.

- [ ] **Step 3: Live triaged run (requires `ANTHROPIC_API_KEY`; ~$1-3)**

This is the spec's real success check. If no key/budget is available, record it as deferred.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export NODE_USE_ENV_PROXY=1   # if behind a proxy
npm run benchmark:differential-fuzz -- --count 2000 --seed 1
```

Confirm: the run completes; `benchmarks/differential-fuzz/results/<subdir>/report.json` is written; the scoreboard prints divergence classes. Per the spec success criterion, inspect whether any class is triaged `likely-exploitable` — those are the candidates worth manual confirmation.

- [ ] **Step 4: Final commit if any fixups were needed**

```bash
git add -A
git commit --signoff -m "chore(diff-fuzz): integration fixups"
```

(Skip if there is nothing to commit.)

---

## Self-Review Notes

- **Spec coverage:** target parsers → Task 4; corpus → Task 2; mutator → Task 3; worker isolation (Approach 1) → Task 5; comparison + dedup → Task 6; LLM triage → Task 7; orchestration + ranking → Task 8; benchmark runner → Task 9; types → Task 1; verification → Task 10. All spec sections covered.
- **Known deviation:** the spec suggests an 80-150 entry corpus; Task 2 ships ~40 family-diverse seeds. The mutator expands these into thousands of inputs, so 40 family-diverse seeds is a defensible MVP — rounding the corpus up is a welcome fast-follow, not a blocker. Flag at plan review if a larger initial corpus is wanted.
- **Type consistency:** `ParserId`, `ParserResult`, `Divergence`, `DivergenceClass`, `TriagedDivergenceClass`, `FuzzReport`, `WorkerLike` are named identically at definition (Tasks 1, 5) and every use site.
- **Testability:** the only code not unit-tested in vitest is the ~12-line `worker.ts` entry script and the real `worker_threads` spawn — both are exercised by Task 10 Step 2 against built output.
