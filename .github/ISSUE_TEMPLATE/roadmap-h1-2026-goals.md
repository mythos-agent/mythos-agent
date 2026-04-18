---
name: "Roadmap — H1 2026 Goals (template, paste once and pin)"
about: "Template for the active 6-month working roadmap issue. Modeled on vLLM #26376."
title: "[Roadmap] mythos-agent H1 2026 Goals"
labels: ["roadmap"]
assignees: []
---

> **Active 6-month plan for mythos-agent (April 2026 → September 2026).**
> Long-term vision lives in [VISION.md](../../blob/main/VISION.md); strategic frame in [ROADMAP.md](../../blob/main/ROADMAP.md). This issue is the *active* working plan and is replaced every six months.
>
> **Conventions:** 🙋 = champion wanted (claim by commenting). ✅ = shipped. 🟡 = in progress. ⚪ = not started. Stage labels: `experimental` → `preview` → `stable` → `deprecated`.
>
> Comments and suggestions for additional items welcome. Material additions go through an RFC.

---

## 🛡 Bucket 1 — Core hardening

The biggest single lever on adopter trust. Theme A from the strategic roadmap.

- [ ] ⚪ **Deterministic taint graph v1** in `src/analysis/taint-engine.ts` — replace AI-prompt taint tracking. Stage: `experimental`. 🙋 (analysis background needed)
- [ ] ⚪ **Deterministic call graph v1** in `src/analysis/call-graph.ts` — inter-procedural. Stage: `experimental`. 🙋
- [ ] 🟡 **80% test coverage across all 44 CLI commands** under `src/cli/commands/`. **Progress:** 7 commands covered by smoke tests in `__tests__/cli-smoke.test.ts` (tools, stats, summary, compliance, doctor, quick, score). Remaining ~37 commands. 🙋 (great first issue — pick one command, follow the smoke-test pattern)
- [x] ✅ **Disambiguate placeholder strings** — `src/agent/prompts.ts` schema example now uses `<CWE-ID, e.g. CWE-89>` (clearer placeholder syntax); `src/rules/registry.ts` rule-pack generator now ships a real demonstration rule (eval() detection) rather than `TODO_REPLACE_WITH_ACTUAL_PATTERN`. Both were intentional templates, not stubs — the change reduces Day-1 visitor confusion when grepping for "TODO" or "XXX".
- [ ] ⚪ **CWE Top 25 audit** across all 49 scanners — every scanner declares which CWEs it covers
- [ ] ⚪ **CODEOWNERS** expanded for distributed review (currently lead-only)

## ⚖️ Bucket 2 — Compliance (TIME-CRITICAL)

EU CRA reporting obligations apply September 11, 2026. This bucket must complete before that date.

- [ ] ⚪ **EU CRA stance published** at `docs/security/cra-stance.md` (declares mythos-agent is *not* an Open-Source Steward; manufacturer guidance)
- [ ] ⚪ **SECURITY.md SLAs** updated to Checkov-style (5-day acknowledgment, 14-day triage, 14-day fix target)
- [ ] ⚪ **OpenSSF Best Practices Badge — Passing** application at bestpractices.dev (67 self-cert criteria)
- [ ] ⚪ **OSPS Baseline L1 (Basic Hygiene)** conformance — 40-control checklist
- [ ] ⚪ **RELEASES.md** published — cadence, branches, LTS, EOL dates

## 🔐 Bucket 3 — Supply-chain hardening

Trivy's GitHub Action was compromised twice in 2025–2026. For a security tool, supply-chain compromise is the #1 incident vector.

- [ ] ⚪ **All GitHub Actions pinned to commit SHA** (audit `.github/workflows/*`)
- [ ] ⚪ **Sigstore release signing** — `.github/workflows/sigstore-release.yml` (cosign for npm + GitHub releases)
- [ ] ⚪ **CycloneDX SBOM** per release — `.github/workflows/sbom.yml`
- [ ] ⚪ **npm provenance attestations** enabled
- [ ] ⚪ **2FA mandatory** at org level
- [ ] ⚪ **Public threat model** at `docs/security/threat-model.md`

## 👥 Bucket 4 — Community on-ramp

- [ ] ⚪ **GitHub Sponsors** button enabled
- [ ] ⚪ **Open Collective** via Open Source Collective fiscal host
- [ ] ⚪ **Mythos-Agent Pioneers leaderboard** — `docs/pioneers.md` + `.github/workflows/pioneers.yml`
- [ ] ⚪ **Scanner plugin SDK** documented at `docs/scanner-sdk.md` + cookie-cutter at `examples/scanners/example-scanner/`
- [ ] ⚪ **RFC process live** — `docs/RFC-TEMPLATE.md` + `docs/rfcs/`
- [ ] ⚪ **CONTRIBUTING.md** expanded with `good-first-issue` taxonomy

## 🧪 Bucket 5 — Benchmark & accuracy

Foundation for B3 (novel-vuln benchmark) and B1 (FP-rate metric).

- [ ] ⚪ **Benchmark spec stub** at `docs/benchmark.md` — methodology + reproducibility instructions
- [ ] ⚪ **First 100 vulns** in the curated 500-vuln corpus
- [ ] ⚪ **Per-release accuracy JSON** committed to repo
- [ ] ⚪ **Comparison runner** vs Semgrep CE / Trivy / OSV-Scanner

---

## 🙋 How to claim a 🙋 item

1. Comment on this issue: *"Claiming X — plan to ship by [date]."*
2. Open a draft PR within ~2 weeks; if not, the claim lapses and the item returns to 🙋.
3. Maintainer adds you to the contributor list and updates this checklist.

## 📅 What comes after H1 2026

H2 2026 will be opened as a new pinned issue in early July 2026 and will lead with **knowledge graph v1** (Theme B) and **agent test harness** (Theme A completion). H1 2026 unfinished items roll forward by default unless explicitly dropped.

---

*Cycle: H1 2026 (April 18 → September 30, 2026). Next cycle issue: H2 2026 — opens July 2026.*
