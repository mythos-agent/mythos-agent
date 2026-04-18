# RFC: <Title>

> Copy this file to `docs/rfcs/NNNN-short-slug.md` (next sequence number, lowercase-hyphenated slug). Open the PR with `[RFC] <Title>` in the title.

| Field | Value |
|---|---|
| **RFC number** | NNNN (assigned by maintainer on first review) |
| **Status** | Draft / Discussion / Accepted / Rejected / Superseded by #NNNN / Withdrawn |
| **Author(s)** | @your-handle |
| **Created** | YYYY-MM-DD |
| **Discussion** | Link to the RFC PR |
| **Affected area(s)** | scanner / analysis / agents / CLI / governance / release / multiple |
| **Required for merge?** | Yes (substantive change) / No (incremental, not RFC-required but submitted for community input) |

## Summary

One paragraph. What does this RFC propose, and what is the problem it solves?

## Motivation

Why are we doing this? Use cases, current pain points, missing capabilities. If this RFC follows from the strategic direction in [ROADMAP.md](../../ROADMAP.md) or [VISION.md](../../VISION.md), link the relevant section.

## Goals

A short bulleted list of what this RFC aims to achieve.

- Goal 1
- Goal 2

## Non-goals

What this RFC explicitly does **not** propose. Important — non-goals prevent scope creep during discussion and protect the surface area against well-intentioned additions.

- Non-goal 1
- Non-goal 2

## Detailed design

The bulk of the RFC. Cover:

- New components, files, or interfaces with their proposed paths under `src/`
- Behavior changes (CLI output, JSON shapes, report formats, agent prompts)
- Backwards compatibility — what breaks, what gets a deprecation cycle, what is wholly new
- Configuration changes (env vars, `.shedu/config.json`, CLI flags)
- Performance implications (with rough estimates if possible)
- Security implications (cross-reference [`docs/security/threat-model.md`](../security/threat-model.md) attack surfaces if applicable)

If you can include a small worked example or pseudo-code, do.

## Alternatives considered

What else did you look at? Why did you reject each?

- **Alternative A** — pros, cons, why rejected
- **Alternative B** — pros, cons, why rejected

A "do nothing" alternative is often worth listing: what is the cost of *not* shipping this?

## Drawbacks

Why might we *not* want to do this? Be honest. RFCs that name their drawbacks accurately are merged faster.

## Migration / rollout

If this RFC introduces breaking change, deprecation, or a phased rollout:

- Deprecation window length (default 6 months per [RELEASES.md](../../RELEASES.md))
- Migration guide location (typically `docs/migrations/`)
- Communication plan (CHANGELOG entry, README banner, blog post)
- Feature-flag plan (if shipping behind an experimental flag first)

## Open questions

Things you want feedback on before this can become Accepted. Phrase as questions, not assertions.

- Open question 1
- Open question 2

## Adoption plan

How will the project know this RFC is implemented? Tie milestones to:

- The current pinned `[Roadmap]` issue (which bucket and item)
- A `tracking-#NNNN` GitHub issue created at Acceptance
- Test coverage targets
- Documentation updates required at acceptance time

## References

- Related RFCs: #NNNN, #NNNN
- External standards / papers / blog posts
- Prior art in comparator projects (Semgrep, Trivy, Nuclei, Garak, etc.)

## Document history

| Date | Change |
|---|---|
| YYYY-MM-DD | Initial draft |
