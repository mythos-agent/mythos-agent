import { describe, it, expect } from "vitest";
import { buildCveInfoFromSeed, runAgentCalibration } from "../agent-runner.js";
import { getSeedPattern } from "../../root-cause/seed-patterns.js";
import { DEFAULT_CONFIG } from "../../../types/index.js";
import type { CalibrationCaseFile } from "../types.js";

// A3b harness smoke tests — sub-PR A3b of variants v2.
//
// These tests verify the harness composition WITHOUT spending API
// credit. The real LLM calls happen via the CLI in
// `benchmarks/variants-calibration/run.ts`; this test layer uses a
// scriptable mock client so CI can run the harness logic offline.
//
// What's exercised:
//   - A1 seed → CveInfo translation (buildCveInfoFromSeed) — the
//     channel by which A1's structured pattern reaches the
//     variant-analyzer prompt.
//   - End-to-end runAgentCalibration loop with a mock client that
//     returns scripted variants.
//   - Skip semantics: missing target / missing seed.
//   - Target-overlap predicate (file-ends-with + line-in-band).

const seededCase: CalibrationCaseFile = {
  ghsa_id: "GHSA-c2qf-rxjj-qqgw",
  cve_id: "CVE-2022-25883",
  vulnerable_commit: "2f738e9a70d9b9468b7b69e9ed3e12418725c650",
  calibration_target: {
    file: "internal/re.js",
    lines: [138, 161],
  },
};

describe("buildCveInfoFromSeed — A1-pattern → CveInfo translation", () => {
  it("populates rootCause with the seed's bug class, summary, AST shape, and data flow", () => {
    const seed = getSeedPattern("CVE-2022-25883");
    expect(seed).not.toBeNull();
    const info = buildCveInfoFromSeed(seededCase, seed!);

    // Identity & severity wiring.
    expect(info.id).toBe("CVE-2022-25883");
    expect(info.cwe).toBe("CWE-1333");
    expect(info.severity).toBe("high");
    expect(info.description).toBe(seed!.summary);

    // The rootCause field is the carrier for A1's structured pattern.
    // These assertions pin the prompt-input shape: a regression here
    // is a regression in what the LLM actually sees.
    expect(info.rootCause).toContain("Bug class: redos-static-template-regex");
    expect(info.rootCause).toContain("(CWE-1333)");
    expect(info.rootCause).toContain('find_ast_pattern tool with kind="template_string"');
    // Each constraint shows up as a bullet in the prompt.
    for (const c of seed!.astShape.constraints) {
      expect(info.rootCause).toContain(c);
    }
    // Data flow source/sink both appear.
    expect(info.rootCause).toContain(seed!.dataFlow.source);
    expect(info.rootCause).toContain(seed!.dataFlow.sink);
  });

  it("falls back to ghsa_id when cve_id is absent", () => {
    const seed = getSeedPattern("GHSA-c2qf-rxjj-qqgw");
    const noCve: CalibrationCaseFile = {
      ...seededCase,
      cve_id: undefined,
    };
    const info = buildCveInfoFromSeed(noCve, seed!);
    expect(info.id).toBe("GHSA-c2qf-rxjj-qqgw");
  });
});

/**
 * Build a mock LLMClient whose single `messages.create` response
 * delivers a final text block containing scripted variants. No tool
 * loop — the harness test cares about the result mapping, not the
 * agentic round-trips (those are exercised by variant-analyzer's
 * own tests).
 */
function mockClientReturningVariants(variants: object[]): {
  messages: { create: () => Promise<unknown> };
} {
  return {
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
              rootCauseAnalysis: "test",
              variants,
            }),
          },
        ],
      }),
    },
  };
}

describe("runAgentCalibration — end-to-end with mock client", () => {
  it("matches when a returned variant lands inside the target band", async () => {
    const client = mockClientReturningVariants([
      {
        file: "internal/re.js",
        line: 138,
        code: "createToken('TILDETRIM', `(\\\\s*)${src[t.LONETILDE]}\\\\s+`, true)",
        similarity: "high",
        explanation: "matched template literal with \\s* adjacent to interpolation",
        rootCauseMatch: "unbounded whitespace + interpolation",
      },
    ]);

    const result = await runAgentCalibration(seededCase, {
      projectPath: "/tmp/fake-project",
      config: { ...DEFAULT_CONFIG, apiKey: "test" },
      client: client as never,
    });

    expect(result.skipped).toBeFalsy();
    expect(result.error).toBeUndefined();
    expect(result.matched).toBe(true);
    expect(result.variantsFound).toBe(1);
    expect(result.overlappingVariants).toBe(1);
    expect(result.target.file).toBe("internal/re.js");
  });

  it("does not match when a returned variant lands outside the target band", async () => {
    const client = mockClientReturningVariants([
      {
        file: "internal/re.js",
        line: 25, // before the [138, 161] band
        code: "createToken('NUMERICIDENTIFIER', '0|[1-9]\\\\d*')",
        similarity: "low",
        explanation: "doesn't actually share the root cause",
        rootCauseMatch: "n/a",
      },
    ]);

    const result = await runAgentCalibration(seededCase, {
      projectPath: "/tmp/fake-project",
      config: { ...DEFAULT_CONFIG, apiKey: "test" },
      client: client as never,
    });

    expect(result.skipped).toBeFalsy();
    expect(result.matched).toBe(false);
    expect(result.variantsFound).toBe(1);
    expect(result.overlappingVariants).toBe(0);
  });

  it("ignores file-path mismatches even when line is in band", async () => {
    const client = mockClientReturningVariants([
      {
        file: "some/other/file.js",
        line: 150,
        code: "irrelevant",
        similarity: "high",
        explanation: "wrong file",
        rootCauseMatch: "n/a",
      },
    ]);

    const result = await runAgentCalibration(seededCase, {
      projectPath: "/tmp/fake-project",
      config: { ...DEFAULT_CONFIG, apiKey: "test" },
      client: client as never,
    });

    expect(result.matched).toBe(false);
    expect(result.overlappingVariants).toBe(0);
  });

  it("treats a path that ends with the target file as a hit (subdir tolerance)", async () => {
    // Variant analyzers sometimes report paths relative to the agent
    // working dir rather than the upstream-repo root. As long as the
    // reported path ENDS with the calibration target's path, count
    // it. Otherwise the harness would miss legitimate hits whenever
    // the model picks a longer prefix.
    const client = mockClientReturningVariants([
      {
        file: "node-semver/internal/re.js",
        line: 148,
        code: "createToken('CARETTRIM', ...)",
        similarity: "high",
        explanation: "yes",
        rootCauseMatch: "unbounded whitespace + interpolation",
      },
    ]);

    const result = await runAgentCalibration(seededCase, {
      projectPath: "/tmp/fake-project",
      config: { ...DEFAULT_CONFIG, apiKey: "test" },
      client: client as never,
    });

    expect(result.matched).toBe(true);
  });

  it("returns 0 variants when the LLM emits no JSON", async () => {
    const client = {
      messages: {
        create: async () => ({
          id: "msg_test",
          type: "message",
          role: "assistant",
          model: "test",
          stop_reason: "end_turn",
          stop_sequence: null,
          usage: { input_tokens: 0, output_tokens: 0 },
          content: [{ type: "text", text: "Sorry, no variants found." }],
        }),
      },
    };

    const result = await runAgentCalibration(seededCase, {
      projectPath: "/tmp/fake-project",
      config: { ...DEFAULT_CONFIG, apiKey: "test" },
      client: client as never,
    });

    expect(result.variantsFound).toBe(0);
    expect(result.matched).toBe(false);
  });
});

describe("runAgentCalibration — skip semantics", () => {
  it("skips a case without calibration_target", async () => {
    const observational: CalibrationCaseFile = {
      ghsa_id: "GHSA-test-0000-0000",
      cve_id: "CVE-9999-99999",
      vulnerable_commit: "0".repeat(40),
    };
    const result = await runAgentCalibration(observational, {
      projectPath: "/tmp/fake",
      config: { ...DEFAULT_CONFIG, apiKey: "test" },
      client: {
        messages: {
          create: async () => {
            throw new Error("LLM should not be invoked when target is missing");
          },
        },
      } as never,
    });
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toMatch(/calibration_target/);
  });

  it("skips a case without an A1 seed pattern", async () => {
    const unseeded: CalibrationCaseFile = {
      ghsa_id: "GHSA-test-9999-9999",
      cve_id: "CVE-1999-9999",
      vulnerable_commit: "0".repeat(40),
      calibration_target: { file: "lib/index.js", lines: [1, 10] },
    };
    const result = await runAgentCalibration(unseeded, {
      projectPath: "/tmp/fake",
      config: { ...DEFAULT_CONFIG, apiKey: "test" },
      client: {
        messages: {
          create: async () => {
            throw new Error("LLM should not be invoked when seed is missing");
          },
        },
      } as never,
    });
    expect(result.skipped).toBe(true);
    expect(result.skipReason).toMatch(/no A1 seed/);
  });
});
