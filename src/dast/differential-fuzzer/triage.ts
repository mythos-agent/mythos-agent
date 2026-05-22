import type { LLMClient } from "../../llm/index.js";
import { extractJson } from "../../agent/json-extract.js";
import type { DivergenceClass, TriagedDivergenceClass, TriageCategory } from "./types.js";

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
