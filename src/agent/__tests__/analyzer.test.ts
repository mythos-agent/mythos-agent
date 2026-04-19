import { describe, it, expect } from "vitest";

import { parseAnalysisResponse } from "../analyzer.js";
import type { Vulnerability } from "../../types/index.js";

// These tests cover the AIAnalyzer's response-parsing pipeline — what
// happens after the 20-turn Claude agentic loop produces a final answer.
// The agentic loop itself still needs proper Anthropic SDK mocking to
// test (tracked as the hardest remaining entry in review-item #14), but
// the parse/verify/discover/dismiss logic is the load-bearing data
// transformation and is testable hermetically via the extracted
// parseAnalysisResponse function.

function vuln(id: string, overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id,
    rule: `test:${id}`,
    title: `Original ${id}`,
    description: "original description",
    severity: "medium",
    category: "test",
    confidence: "medium",
    location: { file: "app.ts", line: 1 },
    ...overrides,
  };
}

describe("parseAnalysisResponse — fallback paths", () => {
  it("returns all phase1 findings unchanged when text has no JSON (model prose-only)", () => {
    // Load-bearing: a truncated response or a refusal must not drop
    // users' phase1 findings. They paid for the deterministic scan; the
    // AI verification is additive, not required.
    const phase1 = [vuln("SPX-0001"), vuln("SPX-0002")];
    const result = parseAnalysisResponse("Sorry, I need more context.", phase1);
    expect(result.confirmed).toEqual(phase1);
    expect(result.discovered).toEqual([]);
    expect(result.dismissedCount).toBe(0);
  });

  it("returns all phase1 findings unchanged when JSON is malformed", () => {
    const phase1 = [vuln("SPX-0001")];
    const result = parseAnalysisResponse(
      '{"verified": [{"originalId": "SPX-0001", "isReal": tru',
      phase1
    );
    expect(result.confirmed).toEqual(phase1);
    expect(result.dismissedCount).toBe(0);
  });

  it("returns empty-confirmed when phase1 is empty and response has no discovered", () => {
    const result = parseAnalysisResponse('{"verified": [], "discovered": []}', []);
    expect(result.confirmed).toEqual([]);
    expect(result.discovered).toEqual([]);
    expect(result.dismissedCount).toBe(0);
  });
});

describe("parseAnalysisResponse — verification", () => {
  it("marks isReal=true findings as aiVerified with confidence='high'", () => {
    const phase1 = [vuln("SPX-0001", { severity: "medium", confidence: "low" })];
    const text = JSON.stringify({
      verified: [{ originalId: "SPX-0001", isReal: true, reasoning: "LGTM" }],
      discovered: [],
    });
    const { confirmed } = parseAnalysisResponse(text, phase1);
    expect(confirmed).toHaveLength(1);
    expect(confirmed[0]).toMatchObject({
      id: "SPX-0001",
      aiVerified: true,
      confidence: "high",
    });
  });

  it("dismisses isReal=false findings (drops from confirmed, increments dismissedCount)", () => {
    const phase1 = [
      vuln("SPX-0001", { title: "Real bug" }),
      vuln("SPX-0002", { title: "False positive" }),
    ];
    const text = JSON.stringify({
      verified: [
        { originalId: "SPX-0001", isReal: true, reasoning: "R" },
        { originalId: "SPX-0002", isReal: false, reasoning: "Actually safe" },
      ],
      discovered: [],
    });
    const { confirmed, dismissedCount } = parseAnalysisResponse(text, phase1);
    expect(confirmed).toHaveLength(1);
    expect(confirmed[0].id).toBe("SPX-0001");
    expect(dismissedCount).toBe(1);
  });

  it("applies adjustedSeverity when the model upgrades/downgrades a finding", () => {
    // The model can return adjustedSeverity to correct an
    // over/under-classified phase1 finding. Pinning this behavior so
    // a refactor doesn't silently drop the override.
    const phase1 = [vuln("SPX-0001", { severity: "medium" })];
    const text = JSON.stringify({
      verified: [
        {
          originalId: "SPX-0001",
          isReal: true,
          reasoning: "This is actually critical in context",
          adjustedSeverity: "critical",
        },
      ],
    });
    const { confirmed } = parseAnalysisResponse(text, phase1);
    expect(confirmed[0].severity).toBe("critical");
  });

  it("preserves original severity when adjustedSeverity is absent or undefined", () => {
    const phase1 = [vuln("SPX-0001", { severity: "high" })];
    const text = JSON.stringify({
      verified: [{ originalId: "SPX-0001", isReal: true, reasoning: "R" }],
    });
    expect(parseAnalysisResponse(text, phase1).confirmed[0].severity).toBe("high");
  });

  it("passes phase1 findings through unchanged when they aren't mentioned in verified[]", () => {
    // Not every phase1 finding gets AI verification — the model might
    // only comment on a subset. Unmentioned findings must NOT be
    // dismissed; they keep original confidence and no aiVerified flag.
    const phase1 = [vuln("SPX-0001"), vuln("SPX-0002", { confidence: "low" })];
    const text = JSON.stringify({
      verified: [{ originalId: "SPX-0001", isReal: true, reasoning: "R" }],
    });
    const { confirmed } = parseAnalysisResponse(text, phase1);
    expect(confirmed).toHaveLength(2);
    const untouched = confirmed.find((f) => f.id === "SPX-0002");
    expect(untouched).toBeDefined();
    expect(untouched?.aiVerified).toBeUndefined();
    expect(untouched?.confidence).toBe("low"); // original
  });
});

describe("parseAnalysisResponse — discovered findings", () => {
  it("assigns SPX-NNNN ids to discovered findings starting after phase1 count", () => {
    // Existing ids: SPX-0001, SPX-0002 (phase1.length = 2).
    // Discovered should be SPX-0003, SPX-0004, ... to avoid collision.
    const phase1 = [vuln("SPX-0001"), vuln("SPX-0002")];
    const text = JSON.stringify({
      verified: [],
      discovered: [
        {
          title: "Discovered A",
          description: "",
          severity: "high",
          category: "authz",
          file: "a.ts",
          line: 10,
        },
        {
          title: "Discovered B",
          description: "",
          severity: "low",
          category: "hygiene",
          file: "b.ts",
          line: 20,
        },
      ],
    });
    const { discovered } = parseAnalysisResponse(text, phase1);
    expect(discovered.map((d) => d.id)).toEqual(["SPX-0003", "SPX-0004"]);
  });

  it("tags discovered findings with rule='ai-discovered' and aiVerified=true", () => {
    const text = JSON.stringify({
      discovered: [
        {
          title: "D",
          description: "",
          severity: "medium",
          category: "c",
          file: "f.ts",
          line: 1,
        },
      ],
    });
    const { discovered } = parseAnalysisResponse(text, []);
    expect(discovered[0]).toMatchObject({
      rule: "ai-discovered",
      aiVerified: true,
      confidence: "high",
    });
  });

  it("preserves CWE, snippet, and location fields on discovered findings", () => {
    const text = JSON.stringify({
      discovered: [
        {
          title: "XXE",
          description: "d",
          severity: "high",
          category: "injection",
          cwe: "CWE-611",
          file: "parser.ts",
          line: 42,
          snippet: "parser.parseFromString(xml)",
        },
      ],
    });
    const { discovered } = parseAnalysisResponse(text, []);
    expect(discovered[0]).toMatchObject({
      cwe: "CWE-611",
      location: {
        file: "parser.ts",
        line: 42,
        snippet: "parser.parseFromString(xml)",
      },
    });
  });
});

describe("parseAnalysisResponse — prose-wrapped JSON", () => {
  it("extracts the JSON object when the model prefaces it with explanation", () => {
    const phase1 = [vuln("SPX-0001")];
    const text = `Let me analyze these findings:

${JSON.stringify({
  verified: [{ originalId: "SPX-0001", isReal: true, reasoning: "R" }],
})}

Let me know if you need more detail.`;
    const { confirmed } = parseAnalysisResponse(text, phase1);
    expect(confirmed).toHaveLength(1);
    expect(confirmed[0].aiVerified).toBe(true);
  });
});
