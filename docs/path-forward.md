# Path Forward — what mythos-agent needs to actually find a real 0-day

> **Status (2026-04-26):** comprehensive plan informed by the [variant-hunt experiment](research/2026-04-26-variant-hunt-experiment.md) which proved variants v1 isn't ready for real bug discovery. This doc lays out the tracks, sequencing, kill criteria, and honest framing for the multi-month path to genuine capability.

## Honest framing first

The original aspiration — "build a tool that finds real 0-days like Anthropic Mythos does" — sets a bar that requires execution sandboxing + frontier-internal-model fine-tuning + multi-month team-scale engineering. mythos-agent is a 50-star OSS project with a single maintainer. Matching Anthropic's autonomy claim isn't a one-quarter goal; it's a multi-year arc, and probably one that requires a different organizational model than "OSS hobby project."

What's actually achievable on a realistic OSS-project budget:

- **Today (already shipped):** an honest static-analysis scanner with multi-model support, an extensible benchmark scoreboard, and a published disclosure policy. The CVE Replay scoreboard at 2 / 5 caught is the credibility floor.
- **Multi-week effort:** wire SmartFuzzer into the hunt pipeline (Track B below). Moves "PoC verified: false hardcoded" to "PoC actually executed in sandbox." This alone changes the project's claim from "LLM-assisted hunting" to "LLM-augmented testing."
- **Multi-month effort:** variants v2 (Track A). Replaces the prompt-only variant search with structured root-cause + AST matching. Per the experiment data, this is what's actually needed for non-zero variant hit rates.
- **Year+ effort:** anything resembling Anthropic Mythos's autonomous-exploit-writing.

This doc plans the multi-week and multi-month tracks honestly. Year+ work is out of scope until the foundation is solid.

## The five tracks

Each track is independently shippable. They can be pursued sequentially (recommended) or in parallel by separate contributors (if the project gets contributors).

### Track A — Variants v2: structured root-cause + AST matching (~6–10 weeks)

**Why:** the experiment proved variants v1's prompt-only approach can't reliably find variants even on matched targets with a frontier model. The fix isn't "better prompt" — it's structured representation.

**Scope:**

- **A1: CVE pattern extraction layer.** New module `src/analysis/root-cause/` that takes a CVE id and produces a structured pattern: the bug class (CWE), the AST shape that's vulnerable, the data-flow direction (source → sink), the language(s) affected. Initial coverage: the 5 CVEs in the existing CVE Replay corpus, used as both seed and validation.
- **A2: AST-based pattern matcher.** Replace `search_code(regex)` (or augment it) with `find_ast_pattern(pattern)` that uses tree-sitter (already a project dependency) to find AST shapes matching the pattern from A1. Tools-layer change in `src/agent/tools.ts`.
- **A3: Calibration corpus.** Take the 2 / 5 caught CVE Replay cases (CVE-2022-25883 semver, CVE-2024-28849 follow-redirects), use them as both seed and target. The variants-v2 tool should produce ≥1 candidate that maps back to the actual fix commit. If it doesn't, the design isn't working.
- **A4: Re-run the variant-hunt experiment.** Same 4 targets, same 2 seeds, same models. Compare to the v1 baseline (0 / 8). Goal: ≥1 verified-real candidate across the 8 runs.

**Cost estimate:** $20–$40 of API credit across calibration + experiment re-runs. Multi-week wall-time mostly in maintainer engineering.

**Kill criteria:** if A3 (calibration on known cases) produces 0 candidates after a serious attempt at the AST matcher, the structured-root-cause approach also isn't enough. At that point, the next bet is Track C (differential fuzzing), not deeper Track A iteration.

**Trigger to start:** now. Tracking issue: TBD (filed alongside this doc).

### Track B — Wire `SmartFuzzer` into the hunt pipeline (~2–4 weeks)

**Why:** Anthropic Mythos's autonomous-exploit-writing depends on a sandbox where the model can compile, run, and observe an exploit. Big Sleep does the same with a Python sandbox. mythos-agent has `src/dast/smart-fuzzer.ts` *already implemented but never wired into the hunt pipeline* — the `verified: false` field on every PoC is hardcoded because the verifier doesn't exist. This is a known capability gap with a clear remedy.

**Scope:**

- **B1: Sandbox layer.** Spawn the target code in a Docker container or a Node `vm` context with no network and limited filesystem. Initial: target the `demo-vulnerable-app/` since it's already containerized.
- **B2: Wire SmartFuzzer into the exploit agent.** When the exploit agent constructs a PoC, hand it to the SmartFuzzer with the target sandbox. SmartFuzzer reports back: "PoC triggered the predicted behavior" / "PoC didn't trigger" / "PoC errored." Update the `verified` field accordingly.
- **B3: Verified-vs-claimed in the scoreboard.** Add a `verified: bool` column to the CVE Replay scoreboard (the per-case verifier output). Distinguishes "we claimed a finding" from "we proved it exploits."
- **B4: Update the README / docs to remove the aspirational claim.** README currently says "Smart fuzzer → dynamically tested" under "Multi-Stage Verification." Make that claim true (post-B2) or scope it down to what's implemented.

**Cost estimate:** ~$10 of API credit for B2's hunt re-runs against demo app. Otherwise pure engineering work.

**Kill criteria:** if B1 (sandbox) turns into a multi-week security minefield (sandbox escapes, resource exhaustion attacks against the host), pivot to using an external sandboxing service (e.g., E2B, Modal) instead of rolling our own.

**Trigger to start:** Track A's A2 (AST matcher) lands, OR Track A is killed at A3. Whichever is first. (Reason: A2's AST matcher informs what kinds of PoCs the exploit agent generates, which informs what the sandbox needs to support.)

### Track C — Differential fuzzing for spec-compliant parsers (~6–10 weeks)

**Why:** Big Sleep's most defensible bug-finding methodology in the SQLite case (CVE-2025-6965) was *fuzzing with structured input*. mythos-agent could pursue a similar angle for parser-class bugs: take a target parser, fuzz it, compare against a reference oracle.

**Scope:**

- **C1: Pick a parser class.** Initial candidate: JSON parsers (lots of npm packages, well-defined oracle in the spec). Or markdown parsers (commonmark spec exists). Or URL parsers (WHATWG URL spec).
- **C2: Build a differential harness.** For each input, run it through the target parser AND a reference oracle. Any output divergence is a potential bug.
- **C3: Run against under-audited parser packages.** Same target-selection criteria as the variant-hunt experiment: >100k weekly downloads, <5k stars, active maintainer.
- **C4: Triage divergences.** Most will be spec-ambiguity, not bugs. Some will be real DoS / parser-confusion vulnerabilities.

**Cost estimate:** mostly engineering time + some API credit for triage assistance.

**Kill criteria:** if C2 (differential harness) doesn't produce any divergences after 1 week of runtime against C3 targets, the methodology isn't catching enough signal. Pivot to a different parser class.

**Trigger to start:** Track B (sandbox) lands. Differential fuzzing depends on sandboxed execution.

### Track D — Supply-chain analysis (~2–4 weeks)

**Why:** lower aspirational ceiling, but realistic time-to-first-finding. Detecting malicious packages (typosquats, suspicious post-install scripts, obfuscated code) is what tools like Socket and Snyk's supply-chain scanner do — and mythos-agent's existing scanners cover much of this surface already (`SupplyChainScanner` exists). Closing this track creates incremental value without requiring research-grade engineering.

**Scope:**

- **D1: Audit existing `SupplyChainScanner`.** What does it catch today? Likely: dangerous install scripts, unpinned deps. What's missing: typosquat detection, obfuscation detection, post-install RCE patterns.
- **D2: Add typosquat detection.** Levenshtein distance + download-count threshold. Flag npm packages whose name is one character off from a popular package.
- **D3: Add obfuscation detection.** Heuristic: ratio of single-letter identifiers, base64-decoded code execution, eval/Function-constructor usage with non-literal arguments.
- **D4: Continuous scanning of new npm publishes.** Daily cron that scans recent publishes against the heuristics. File reports for high-confidence findings.

**Cost estimate:** mostly engineering time. Scanning is cheap.

**Kill criteria:** if Socket / Snyk / etc. ship the same features faster, deprecate this track and integrate with their data instead.

**Trigger to start:** any time. Independent of Tracks A–C.

### Track E — AI-assisted manual review (always-on)

**Why:** the variants/hunt pipeline doesn't have to be autonomous to be useful. A maintainer doing security review of an OSS package can use mythos-agent's recon + hypothesis output as *input* to their own analysis, even if the tool itself doesn't produce verified findings. This is the realistic "find a real bug today" path — and it's how most security researchers actually work.

**Scope:**

- **E1: Document the workflow.** Update `docs/DEMO-SCRIPT.md` with the manual-review use case. Position mythos-agent as "the assistant in your security review," not "the autonomous security agent."
- **E2: Improve hypothesis output for human readers.** Less "JSON dump"; more "ranked list of things to check, with rationale." Recon + hypothesis output should be human-actionable.
- **E3: Track manual-review wins.** When a maintainer uses mythos-agent during a security review and finds something, log it (with their consent). These become case studies in the README's "what we've found" section.

**Cost estimate:** continuous, low. Mostly docs work.

**Kill criteria:** none — this track is sustainable indefinitely.

**Trigger to start:** now. Independent of A–D.

## Sequencing — recommended order

For a single maintainer, attempting all 5 tracks in parallel is a recipe for nothing finishing. Sequence:

| Phase | Tracks active | Trigger to advance | Wall-time estimate |
|---|---|---|---|
| 1 (now) | E (continuous), file all tracking issues | none — phase 1 is structural prep | 1 week |
| 2 | A (variants v2) + E | A1 + A2 land | 4–6 weeks |
| 3 | A3 (calibration) + B (sandbox) + E | A3 hit-rate measured + B1 sandbox secure | 4–6 weeks |
| 4 | C (differential fuzzing) + D (supply chain) + E | A4 re-run shows ≥1 verified candidate | indefinite |

Phases 2–3 are the multi-month commit. The phase 1 work (this PR) is structural — write the plan, file issues, set expectations.

## Kill criteria — when to abandon the "find a 0-day" goal entirely

- **6 months from now** (2026-10-26), if Track A's calibration (A3) is producing 0 hits AND Track B's sandbox isn't catching exploits AND Track C's differential fuzzing is finding only spec-ambiguity divergences → the project's value is in incremental scanner improvements (Track D, Track E) and the "0-day finder" framing should be retired.
- **12 months from now** (2027-04-26), if no real disclosed vulnerability has been attributed to a mythos-agent run → re-evaluate the project's positioning. Either pivot to "developer security review tool" (which is genuinely valuable and achievable) or sunset the autonomy claims entirely.

These dates are written in advance precisely so they can't be moved later when the goalposts get inconvenient. Same discipline as the [outbound disclosure policy](security/outbound-disclosure.md) — pre-commit when it's cheap.

## What this plan deliberately does not do

- **Promise a 0-day finding.** The variant-hunt experiment proved that's not on the menu in v1, and even v2 needs months of work before it's a reasonable bet.
- **Sequence Tracks A and B in parallel for a single maintainer.** Both are deep work; doing them together fragments attention and produces no shipped capability.
- **Compete with commercial security-research teams.** Anthropic Mythos has Anthropic's research budget; Google Big Sleep has DeepMind. mythos-agent's path is open-source-tool-with-honest-positioning, not parity with those teams.
- **Wire complex provider-abstraction frameworks.** OpenAI SDK + Anthropic SDK is enough; per the multi-model plan's out-of-scope section, custom abstraction layers always rot.
- **Build a fuzzer from scratch.** SmartFuzzer already exists; the work in Track B is wiring, not building.

## See also

- [`docs/research/2026-04-26-variant-hunt-experiment.md`](research/2026-04-26-variant-hunt-experiment.md) — the experiment data this plan is informed by.
- [`docs/multi-model.md`](multi-model.md) — the multi-model infrastructure that's a prerequisite for cost-bounded experimentation across tracks.
- [`docs/security/outbound-disclosure.md`](security/outbound-disclosure.md) — the policy that gates any actual finding from any track.
- [`docs/benchmarks/external-scores.md`](benchmarks/external-scores.md) — the credibility scoreboard that all tracks should keep moving.
- Tracking issues (filed alongside this doc): variants v2 (TBD), SmartFuzzer wiring (TBD).
