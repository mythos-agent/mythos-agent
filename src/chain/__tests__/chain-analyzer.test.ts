import { describe, it, expect } from "vitest";

import { ChainAnalyzer, parseChainsFromText } from "../chain-analyzer.js";
import { DEFAULT_CONFIG, type MythosConfig, type Vulnerability } from "../../types/index.js";

// ChainAnalyzer has two interesting surfaces:
//   1. Short-circuit paths in `analyzeChains` — no apiKey / <2 vulns.
//      Tested directly without any LLM client.
//   2. The LLM-response parser `parseChainsFromText`, extracted so tests
//      can hit the data-shaping logic (JSON extraction, unknown-vuln-id
//      filtering, <2-after-filter drop, CHAIN-NNN id formatting)
//      without mocking Anthropic.

function noApiKeyConfig(): MythosConfig {
  const c = structuredClone(DEFAULT_CONFIG);
  c.apiKey = undefined;
  return c;
}

function withApiKeyConfig(): MythosConfig {
  const c = structuredClone(DEFAULT_CONFIG);
  c.apiKey = "test-key-not-used-in-short-circuit-paths";
  return c;
}

function vuln(id: string, overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id,
    rule: `test:${id}`,
    title: `Test ${id}`,
    description: "",
    severity: "high",
    category: "test",
    confidence: "high",
    location: { file: "app.ts", line: 1 },
    ...overrides,
  };
}

describe("ChainAnalyzer — short-circuit paths", () => {
  it("returns [] immediately when config.apiKey is undefined, regardless of vuln count", async () => {
    // Pins the no-apiKey early return. The CLI and Orchestrator both rely
    // on this: they construct a ChainAnalyzer unconditionally and let
    // this gate decide whether to actually call the model. Removing the
    // gate would attempt an Anthropic call with an undefined key.
    const analyzer = new ChainAnalyzer(noApiKeyConfig());
    const chains = await analyzer.analyzeChains(
      [vuln("SPX-0001"), vuln("SPX-0002"), vuln("SPX-0003")],
      "/tmp"
    );
    expect(chains).toEqual([]);
  });

  it("returns [] when given 0 vulnerabilities even with a key", async () => {
    const analyzer = new ChainAnalyzer(withApiKeyConfig());
    const chains = await analyzer.analyzeChains([], "/tmp");
    expect(chains).toEqual([]);
  });

  it("returns [] when given 1 vulnerability (a chain needs 2+) even with a key", async () => {
    const analyzer = new ChainAnalyzer(withApiKeyConfig());
    const chains = await analyzer.analyzeChains([vuln("SPX-0001")], "/tmp");
    expect(chains).toEqual([]);
  });
});

describe("parseChainsFromText — JSON extraction robustness", () => {
  it("returns [] when the response contains no JSON object", () => {
    expect(parseChainsFromText("Sorry, I can't find any chains.", [])).toEqual([]);
  });

  it("returns [] when the JSON present is malformed (syntax error)", () => {
    // The model occasionally returns truncated or invalid JSON — the
    // parser must swallow the SyntaxError and fail closed (no chains)
    // rather than propagate it to the caller.
    const text = '{"chains": [{"title": "X", "vulnerabilityIds": ["SPX-1"';
    expect(parseChainsFromText(text, [])).toEqual([]);
  });

  it("returns [] when the `chains` field is missing from an otherwise valid object", () => {
    const text = '{"other": "data"}';
    expect(parseChainsFromText(text, [])).toEqual([]);
  });

  it("returns [] when `chains` is explicitly empty", () => {
    expect(parseChainsFromText('{"chains": []}', [])).toEqual([]);
  });
});

describe("parseChainsFromText — vuln-ID resolution + chain filtering", () => {
  it("resolves vulnerability ids against the supplied list and preserves the full Vulnerability", () => {
    const a = vuln("SPX-0001", { title: "SQLi" });
    const b = vuln("SPX-0002", { title: "XSS" });
    const text = JSON.stringify({
      chains: [
        {
          title: "SQLi → XSS",
          severity: "critical",
          vulnerabilityIds: ["SPX-0001", "SPX-0002"],
          narrative: "An attacker exploits SQLi then pivots to XSS.",
          impact: "Account takeover",
        },
      ],
    });
    const chains = parseChainsFromText(text, [a, b]);
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({
      id: "CHAIN-001",
      title: "SQLi → XSS",
      severity: "critical",
      narrative: "An attacker exploits SQLi then pivots to XSS.",
      impact: "Account takeover",
    });
    // Full Vulnerability objects preserved, not just ids.
    expect(chains[0].vulnerabilities).toEqual([a, b]);
  });

  it("silently drops vulnerability ids the model hallucinates that aren't in the supplied list", () => {
    // Guards against the model citing a plausible-looking but
    // nonexistent vuln id. The parser must drop the id without
    // throwing, and keep the chain if >= 2 valid ids remain.
    const a = vuln("SPX-0001");
    const b = vuln("SPX-0002");
    const text = JSON.stringify({
      chains: [
        {
          title: "Chain with one hallucinated id",
          severity: "high",
          vulnerabilityIds: ["SPX-0001", "SPX-9999-FAKE", "SPX-0002"],
          narrative: "N",
          impact: "I",
        },
      ],
    });
    const chains = parseChainsFromText(text, [a, b]);
    expect(chains).toHaveLength(1);
    expect(chains[0].vulnerabilities.map((v) => v.id)).toEqual(["SPX-0001", "SPX-0002"]);
  });

  it("discards a chain entirely when fewer than 2 valid vulns remain after filtering", () => {
    // A chain of 1 isn't a chain. Hallucinated ids that degrade the
    // count below 2 collapse the whole entry.
    const a = vuln("SPX-0001");
    const text = JSON.stringify({
      chains: [
        {
          title: "Would-be chain",
          severity: "high",
          vulnerabilityIds: ["SPX-0001", "SPX-FAKE"],
          narrative: "N",
          impact: "I",
        },
      ],
    });
    expect(parseChainsFromText(text, [a])).toEqual([]);
  });

  it("assigns CHAIN-NNN ids in array order, including positions where chains were dropped", () => {
    // The id reflects the LLM's array position (`i` in the .map),
    // NOT the filtered index. So if chain 0 is dropped and chain 1
    // survives, the surviving chain is CHAIN-002, not CHAIN-001.
    // This preserves traceability back to the model's raw response
    // when debugging.
    const a = vuln("SPX-0001");
    const b = vuln("SPX-0002");
    const text = JSON.stringify({
      chains: [
        {
          title: "Dropped — only 1 valid vuln",
          severity: "medium",
          vulnerabilityIds: ["SPX-FAKE", "SPX-0001"],
          narrative: "N",
          impact: "I",
        },
        {
          title: "Survivor",
          severity: "high",
          vulnerabilityIds: ["SPX-0001", "SPX-0002"],
          narrative: "N",
          impact: "I",
        },
      ],
    });
    const chains = parseChainsFromText(text, [a, b]);
    expect(chains).toHaveLength(1);
    expect(chains[0].id).toBe("CHAIN-002");
    expect(chains[0].title).toBe("Survivor");
  });

  it("extracts JSON even when surrounded by narration prose", () => {
    // Claude often prefaces or follows JSON with explanation. The regex
    // /\{[\s\S]*\}/ grabs the outermost brace-pair.
    const a = vuln("SPX-0001");
    const b = vuln("SPX-0002");
    const text = `Here is my analysis:

${JSON.stringify({
  chains: [
    {
      title: "A",
      severity: "low",
      vulnerabilityIds: ["SPX-0001", "SPX-0002"],
      narrative: "N",
      impact: "I",
    },
  ],
})}

Let me know if you need more detail.`;
    const chains = parseChainsFromText(text, [a, b]);
    expect(chains).toHaveLength(1);
    expect(chains[0].title).toBe("A");
  });
});
