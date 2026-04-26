import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RootCauseExtractor, parsePattern, buildExtractionPrompt } from "../extractor.js";
import { SEED_PATTERNS, SEEDED_IDS, getSeedPattern } from "../seed-patterns.js";
import { DEFAULT_CONFIG } from "../../../types/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CVE_REPLAY_CASES = path.resolve(__dirname, "../../../../benchmarks/cve-replay/cases");

describe("seed corpus — completeness vs CVE Replay cases", () => {
  // The seed corpus exists to be the calibration ground truth for A3
  // (see docs/path-forward.md Track A). If the CVE Replay corpus and
  // the seed corpus drift apart, A3's "AST matcher must hit these"
  // assertion has nothing to anchor against. This test fails loudly
  // when somebody adds a case file without adding the matching seed
  // (or vice versa).
  it("has a seed for every CVE Replay case file", () => {
    const caseFiles = fs
      .readdirSync(CVE_REPLAY_CASES)
      .filter((f) => f.endsWith(".json") && !f.startsWith("_"));
    expect(caseFiles.length).toBeGreaterThan(0);

    for (const file of caseFiles) {
      const json = JSON.parse(fs.readFileSync(path.join(CVE_REPLAY_CASES, file), "utf-8")) as {
        ghsa_id: string;
        cve_id: string;
      };

      const byGhsa = getSeedPattern(json.ghsa_id);
      const byCve = getSeedPattern(json.cve_id);
      expect(byGhsa, `seed missing for ${json.ghsa_id} (case file: ${file})`).not.toBeNull();
      expect(byCve, `seed missing for ${json.cve_id}`).not.toBeNull();
      expect(byGhsa).toBe(byCve);
    }
  });

  it("does not contain seeds for CVEs absent from the corpus", () => {
    // Inverse direction: if a seed exists, the CVE Replay case should
    // also exist. Stops the seed corpus from accumulating untested
    // patterns that A3's calibration can't validate against.
    const caseFiles = fs
      .readdirSync(CVE_REPLAY_CASES)
      .filter((f) => f.endsWith(".json") && !f.startsWith("_"));
    const corpusCveIds = new Set(
      caseFiles.map((f) => {
        const json = JSON.parse(fs.readFileSync(path.join(CVE_REPLAY_CASES, f), "utf-8")) as {
          cve_id: string;
        };
        return json.cve_id;
      })
    );

    for (const seed of SEED_PATTERNS) {
      expect(
        corpusCveIds.has(seed.cveId),
        `seed for ${seed.cveId} has no matching CVE Replay case`
      ).toBe(true);
    }
  });
});

describe("getSeedPattern — id canonicalization", () => {
  it("looks up by CVE id (case-insensitive)", () => {
    expect(getSeedPattern("CVE-2022-25883")?.cveId).toBe("CVE-2022-25883");
    expect(getSeedPattern("cve-2022-25883")?.cveId).toBe("CVE-2022-25883");
    expect(getSeedPattern("  CVE-2022-25883  ")?.cveId).toBe("CVE-2022-25883");
  });

  it("looks up by GHSA id", () => {
    expect(getSeedPattern("GHSA-c2qf-rxjj-qqgw")?.cveId).toBe("CVE-2022-25883");
  });

  it("returns null for unseeded ids", () => {
    expect(getSeedPattern("CVE-9999-99999")).toBeNull();
    expect(getSeedPattern("not-a-cve-id")).toBeNull();
  });

  it("exposes a SEEDED_IDS set covering both CVE and GHSA forms", () => {
    expect(SEEDED_IDS.has("CVE-2022-25883")).toBe(true);
    expect(SEEDED_IDS.has("GHSA-C2QF-RXJJ-QQGW")).toBe(true);
  });
});

describe("seed shape — structural invariants", () => {
  // These invariants are what A2's AST matcher and A3's calibration
  // rely on. Drift here would silently break downstream layers.
  it.each(SEED_PATTERNS.map((s) => [s.cveId, s] as const))(
    "%s has all required fields populated",
    (_id, seed) => {
      expect(seed.cveId).toMatch(/^CVE-\d{4}-\d{4,}$/);
      expect(seed.bugClass).toMatch(/^[a-z][a-z0-9-]+$/);
      expect(seed.cwe).toMatch(/^CWE-\d+$/);
      expect(seed.languages.length).toBeGreaterThan(0);
      expect(seed.astShape.kind.length).toBeGreaterThan(0);
      expect(seed.astShape.constraints.length).toBeGreaterThan(0);
      expect(seed.dataFlow.source.length).toBeGreaterThan(0);
      expect(seed.dataFlow.sink.length).toBeGreaterThan(0);
      expect(seed.summary.length).toBeGreaterThan(20);
    }
  );

  it("uses distinct bugClass labels for the two CWE-1333 ReDoS cases", () => {
    // Calibration anchor: CVE-2022-25883 (semver) and CVE-2024-45296
    // (path-to-regexp) are both CWE-1333 but have completely different
    // AST shapes. The bugClass must distinguish them — otherwise the
    // AST matcher can't tell which pattern to apply, and A3 can't
    // measure whether the right pattern fired.
    const semver = getSeedPattern("CVE-2022-25883");
    const ptr = getSeedPattern("CVE-2024-45296");
    expect(semver?.cwe).toBe("CWE-1333");
    expect(ptr?.cwe).toBe("CWE-1333");
    expect(semver?.bugClass).not.toBe(ptr?.bugClass);
  });
});

describe("parsePattern — JSON parser tolerance", () => {
  // Mirrors the variant-analyzer.ts parser-tolerance contract: when a
  // small or quantized model emits truncated/garbled JSON, the
  // pipeline must keep working. parsePattern returns null instead of
  // throwing; the caller decides whether to retry.

  it("returns null when text contains no JSON substring", () => {
    expect(parsePattern("Just prose, no JSON.", "CVE-2022-25883")).toBeNull();
  });

  it("returns null when text contains malformed JSON without throwing", () => {
    expect(() => parsePattern("{not valid json", "CVE-x")).not.toThrow();
    expect(parsePattern("{not valid json", "CVE-x")).toBeNull();
  });

  it("falls back to safe defaults when fields are missing", () => {
    const out = parsePattern('{"summary":"a short note"}', "CVE-1999-0001");
    expect(out).not.toBeNull();
    expect(out?.cveId).toBe("CVE-1999-0001");
    expect(out?.bugClass).toBe("");
    expect(out?.cwe).toBe("");
    expect(out?.languages).toEqual([]);
    expect(out?.astShape.kind).toBe("");
    expect(out?.astShape.constraints).toEqual([]);
    expect(out?.dataFlow.source).toBe("");
    expect(out?.dataFlow.sink).toBe("");
    expect(out?.summary).toBe("a short note");
  });

  it("preserves an inline cveId from the LLM output", () => {
    // If the LLM echoes the CVE id back in its response we trust it
    // over the fallback. Lets a future caller pass `id: ""` for
    // open-ended exploration without losing track of which CVE the
    // model picked.
    const text = JSON.stringify({ cveId: "CVE-2024-12345", summary: "x" });
    expect(parsePattern(text, "fallback-id")?.cveId).toBe("CVE-2024-12345");
  });

  it("filters non-string entries out of array fields", () => {
    const text = JSON.stringify({
      languages: ["javascript", 42, null, "typescript"],
      astShape: { kind: "regex_literal", constraints: ["a", 1, "b"] },
    });
    const out = parsePattern(text, "CVE-x");
    expect(out?.languages).toEqual(["javascript", "typescript"]);
    expect(out?.astShape.constraints).toEqual(["a", "b"]);
  });

  it("round-trips a fully-valid JSON pattern", () => {
    const seed = SEED_PATTERNS[0];
    const out = parsePattern(JSON.stringify(seed), seed.cveId);
    expect(out).toMatchObject({
      cveId: seed.cveId,
      bugClass: seed.bugClass,
      cwe: seed.cwe,
      languages: seed.languages,
      astShape: seed.astShape,
      dataFlow: seed.dataFlow,
      summary: seed.summary,
    });
  });
});

describe("buildExtractionPrompt — few-shot anchoring", () => {
  it("includes the first two seed patterns as examples", () => {
    const prompt = buildExtractionPrompt({
      id: "CVE-9999-99999",
      description: "A hypothetical bug.",
    });
    expect(prompt).toContain(SEED_PATTERNS[0].cveId);
    expect(prompt).toContain(SEED_PATTERNS[1].cveId);
    expect(prompt).toContain("CVE-9999-99999");
    expect(prompt).toContain("A hypothetical bug.");
  });

  it("optionally embeds CWE / language / affected code", () => {
    const prompt = buildExtractionPrompt({
      id: "CVE-9999-99999",
      description: "x",
      cwe: "CWE-89",
      language: "python",
      affectedCode: "cursor.execute('SELECT * FROM t WHERE id=' + user_id)",
    });
    expect(prompt).toContain("CWE: CWE-89");
    expect(prompt).toContain("Primary language: python");
    expect(prompt).toContain("cursor.execute");
  });
});

describe("RootCauseExtractor — constructor wiring (multi-model)", () => {
  // Mirrors variant-analyzer.test.ts: the constructor must go through
  // the createLLMClient factory so `provider: openai` users get an
  // OpenAILLMClient just like the four hunt agents do (PRs #44/#46/
  // #47). The factory's contract is "returns SOMETHING that satisfies
  // LLMClient" — we don't introspect the concrete class.
  it("constructs without throwing on the default config (Tier 1 Anthropic)", () => {
    const config = { ...DEFAULT_CONFIG, apiKey: "test-key" };
    const extractor = new RootCauseExtractor(config);
    expect(extractor).toBeDefined();
  });

  it("constructs through the factory on provider: openai (Tier 2)", () => {
    const config = {
      ...DEFAULT_CONFIG,
      apiKey: "test-key",
      provider: "openai",
      baseURL: "https://example.invalid/v1",
    };
    const extractor = new RootCauseExtractor(config);
    expect(extractor).toBeDefined();
  });

  it("accepts an injected client (test-mock back-compat)", () => {
    const fakeClient = {
      messages: {
        create: async () => {
          throw new Error("not exercised in this test");
        },
      },
    };
    const config = { ...DEFAULT_CONFIG, apiKey: "test-key" };
    const extractor = new RootCauseExtractor(config, fakeClient as never);
    expect(extractor).toBeDefined();
  });
});

describe("RootCauseExtractor.extract — seed-first behavior", () => {
  it("returns the seed pattern without calling the LLM for seeded CVEs", async () => {
    let called = false;
    const fakeClient = {
      messages: {
        create: async () => {
          called = true;
          throw new Error("LLM should not be called for seeded CVEs");
        },
      },
    };
    const extractor = new RootCauseExtractor(
      { ...DEFAULT_CONFIG, apiKey: "test-key" },
      fakeClient as never
    );
    const result = await extractor.extract({
      id: "CVE-2022-25883",
      description: "ignored when seeded",
    });
    expect(called).toBe(false);
    expect(result?.cveId).toBe("CVE-2022-25883");
    expect(result?.bugClass).toBe("redos-static-template-regex");
  });

  it("calls the LLM when skipSeed is set, even for seeded CVEs", async () => {
    let called = false;
    const fakeClient = {
      messages: {
        create: async () => {
          called = true;
          return {
            id: "msg_test",
            type: "message",
            role: "assistant",
            model: "test",
            stop_reason: "end_turn",
            stop_sequence: null,
            usage: { input_tokens: 0, output_tokens: 0 },
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  bugClass: "regenerated",
                  cwe: "CWE-1333",
                  languages: ["javascript"],
                  astShape: { kind: "regex_literal", constraints: ["x"] },
                  dataFlow: { source: "s", sink: "k" },
                  summary: "regenerated from LLM",
                }),
              },
            ],
          };
        },
      },
    };
    const extractor = new RootCauseExtractor(
      { ...DEFAULT_CONFIG, apiKey: "test-key" },
      fakeClient as never
    );
    const result = await extractor.extract(
      { id: "CVE-2022-25883", description: "force LLM path" },
      { skipSeed: true }
    );
    expect(called).toBe(true);
    expect(result?.bugClass).toBe("regenerated");
  });

  it("falls back to LLM extraction for unseeded CVEs", async () => {
    const fakeClient = {
      messages: {
        create: async () => ({
          id: "msg_test",
          type: "message",
          role: "assistant",
          model: "test",
          stop_reason: "end_turn",
          stop_sequence: null,
          usage: { input_tokens: 0, output_tokens: 0 },
          content: [
            {
              type: "text",
              text: JSON.stringify({
                bugClass: "sql-injection-string-concat",
                cwe: "CWE-89",
                languages: ["python"],
                astShape: {
                  kind: "call_expression",
                  constraints: ["callee is cursor.execute", "argument built by + concatenation"],
                },
                dataFlow: {
                  source: "user_id query parameter",
                  sink: "SQL execute path",
                },
                summary: "Classic string-concatenation SQL injection.",
              }),
            },
          ],
        }),
      },
    };
    const extractor = new RootCauseExtractor(
      { ...DEFAULT_CONFIG, apiKey: "test-key" },
      fakeClient as never
    );
    const result = await extractor.extract({
      id: "CVE-9999-99999",
      description: "Hypothetical SQL injection",
      cwe: "CWE-89",
    });
    expect(result?.cveId).toBe("CVE-9999-99999");
    expect(result?.bugClass).toBe("sql-injection-string-concat");
    expect(result?.cwe).toBe("CWE-89");
  });

  it("returns null when the LLM emits non-JSON output", async () => {
    const fakeClient = {
      messages: {
        create: async () => ({
          id: "msg_test",
          type: "message",
          role: "assistant",
          model: "test",
          stop_reason: "end_turn",
          stop_sequence: null,
          usage: { input_tokens: 0, output_tokens: 0 },
          content: [{ type: "text", text: "Sorry, I can't help with that." }],
        }),
      },
    };
    const extractor = new RootCauseExtractor(
      { ...DEFAULT_CONFIG, apiKey: "test-key" },
      fakeClient as never
    );
    const result = await extractor.extract({
      id: "CVE-9999-99999",
      description: "Hypothetical bug",
    });
    expect(result).toBeNull();
  });
});
