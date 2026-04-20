# mythos-agent brand system

Single source of truth for palette, typography, mascot usage, and accessibility rules. If you're adding a new reporter, UI surface, or visual asset — read this first. If you're tempted to invent a new hex value, don't.

Runtime constants live in [`src/report/brand.ts`](src/report/brand.ts). Import from there; never hand-code hex values in a reporter.

## Palette

### Logo palette (4 colors — used for the mark itself)

| Role | Token | Hex | Used in |
|---|---|---|---|
| Primary | `BRAND.violet` | `#5B2A86` | Wordmark, header accents, chain cards, section dividers |
| Accent | `BRAND.cyan` | `#22D3EE` | Code text, links, info severity, social-preview tagline |
| Surface (light) | `BRAND.offWhite` | `#FAFAFA` | Text on dark, belly/muzzle in mascot art |
| Surface (dark) | `BRAND.nearBlack` | `#0B0B0F` | Report/dashboard background, social preview bg |

### Severity palette (6 colors — shared across reporters via `SEVERITY_HEX`)

| Severity | Hex | Notes |
|---|---|---|
| `critical` | `#EF4444` | Standard semantic red; industry expectation |
| `high` | `#FB923C` | **Reuses brand amber** — on-brand AND semantically "warning orange" |
| `medium` | `#F59E0B` | Amber-yellow |
| `low` | `#22D3EE` | **Reuses brand cyan** — on-brand AND semantically "info" |
| `verified` | `#10B981` | Emerald — AI-confirmed findings, trust-score good |
| `dismissed` | `#9CA3AF` | Muted gray |

### Derived neutrals (dark-mode card surfaces)

| Token | Hex | Purpose |
|---|---|---|
| `BRAND.surface` | `#14141A` | Card backgrounds on dark |
| `BRAND.surfaceRaised` | `#1C1C24` | Hover / raised card state |
| `BRAND.border` | `#2A2A33` | Card dividers |
| `BRAND.borderStrong` | `#3A3A44` | Interactive element borders |
| `BRAND.muted` | `#9CA3AF` | Secondary text — passes WCAG AA on `nearBlack` |
| `BRAND.subtle` | `#6B7280` | Metadata text (use only on light backgrounds) |

### Illustration accents (mascot art ONLY — never on the logo mark)

- Warm pink `#F472B6` — mascot tongue
- Amber `#FB923C` — mascot collar charm (doubles as severity `high`)

Mascot SVG files may also contain derived shades (for shading/fur texture) that are not part of the core palette but are considered on-brand provided they stay within ±15% luminance of a declared color.

## Typography

| Role | Stack | Notes |
|---|---|---|
| UI (reports, dashboard, docs) | `-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif` | Fast-loading system font stack. Do not load web fonts for UI. |
| Wordmark (banner, lockup) | `"Inter Display", "Helvetica Neue", Helvetica, Arial, sans-serif` | GitHub sanitizes SVG fonts, so real typography requires a Figma outlining pass for pixel-perfect Geist. Current SVG uses Inter Display fallback. |
| Code (vuln locations, snippets, chain steps) | `"Geist Mono", ui-monospace, SFMono-Regular, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace` | Geist Mono preferred when installed locally; clean system fallback otherwise. No CDN link — reports stay self-contained. |

## Mascot tiering (who uses Cerby, who doesn't)

GitHub's own [brand guidelines](https://brand.github.com/graphic-elements/mascots) explicitly advise against using mascots in serious contexts (security, money, enterprise, apologies). mythos-agent is a security tool, so Cerby is tiered by surface type:

### Warm surfaces — Cerby welcome

- README banner (current: `assets/cerby-banner.svg`)
- GitHub org avatar + social preview
- Landing page hero
- Docs homepage, onboarding screens
- Error / empty states, friendly 404
- Swag, stickers, Discord emoji

### Serious surfaces — wordmark + chip only, no Cerby body

- SARIF reports and CI annotations
- CLI policy violations, terminal scan output
- Enterprise documentation
- Security advisories
- Anything a CISO is reading to triage a CVE

HTML report header currently shows a small 64px Cerby. This is a borderline surface — Cerby is small enough to read as a chip rather than a cartoon. Revisit if enterprise customers flag it.

## WCAG allowed / disallowed pairings

Target: **WCAG AA** (4.5:1 for text, 3:1 for large text / UI components). Verify new combinations at [webaim.org/resources/contrastchecker](https://webaim.org/resources/contrastchecker/).

### ✅ Allowed text pairings

| Text | Background | Contrast | Use |
|---|---|---|---|
| `BRAND.violet` | `BRAND.offWhite` | 7.9:1 (AAA) | Wordmark on light bg |
| `BRAND.offWhite` | `BRAND.nearBlack` | 17:1 (AAA) | Primary text on dark |
| `BRAND.cyan` | `BRAND.nearBlack` | 11.5:1 (AAA) | Links, code text on dark |
| `BRAND.muted` | `BRAND.nearBlack` | ~6:1 (AA) | Secondary text on dark |
| `SEVERITY_HEX.*` | `BRAND.nearBlack` | ≥4.5:1 | All severity labels on dark — verified |

### ❌ Disallowed text pairings

| Text | Background | Contrast | Why |
|---|---|---|---|
| `BRAND.cyan` | `BRAND.offWhite` | 1.7:1 | Both too bright — fails AA |
| `BRAND.violet` | `BRAND.nearBlack` | 2.4:1 | Both too dark — fails AA |
| `BRAND.subtle` (`#6B7280`) | `BRAND.nearBlack` | ~3.8:1 | Fails AA for body text; OK for large text (18px+) only |

## Asset catalog

All visual assets live in [`assets/`](assets/):

| File | Purpose | Notes |
|---|---|---|
| `cerby-hero.svg` | 2048×2048 canonical seated Cerby | Source for README banner, social preview, org avatar |
| `cerby-chip.svg` | Head-only chip mark | Small surfaces (favicon source, UI chips) |
| `cerby-banner.svg` | 1200×300 README lockup | Hero + wordmark + tagline, transparent bg |
| `cerby-banner-social.svg` | 1280×640 source for social preview | Dark bg, render to `cerby-banner-social.png` for upload |
| `cerby-banner-social.png` | 1280×640 GitHub social preview | Upload via repo Settings → Social preview |
| `favicon.svg`, `favicon.ico`, `favicon-96x96.png` | Browser tab icons | Inlined into HTML reports as base64 |
| `apple-touch-icon.png`, `web-app-manifest-*.png`, `site.webmanifest` | PWA icons | For future `mythos-agent.com` domain |

## Don't-do rules

1. **Don't invent hex values.** Import from `src/report/brand.ts`. If you need a shade that doesn't exist, add it there with a name and a justification comment.
2. **Don't use Cerby on serious surfaces** (see mascot tiering above). The wordmark + chip suffice.
3. **Don't put `BRAND.cyan` on `BRAND.offWhite`** or `BRAND.violet` on `BRAND.nearBlack` as text. They fail AA.
4. **Don't load web fonts in reports.** Reports must open offline. Use the declared stacks; `Geist Mono` only loads if the user has it installed locally.
5. **Don't create new severity color sets.** If you think you need one, you're wrong — use `SEVERITY_HEX`.
6. **Don't use raster PNG for the logo** where an SVG will render. Only the 1280×640 social preview needs to be PNG (GitHub requirement).

## Revision policy

When changing a brand value:

1. Update `src/report/brand.ts` (the runtime source of truth).
2. Update this file (the doc source of truth).
3. Update `assets/BRAND.md` references in any markdown that cites specific hex values.
4. Run `npx tsc --noEmit` to ensure no reporter broke.
5. Commit both files together with a `chore(brand):` or `feat(brand):` scope.
