/**
 * Shared brand palette for every HTML/SVG surface. Single source of truth.
 * Any new reporter must import from here. Do not inline new hex values.
 *
 * Rationale + WCAG pairings: see /BRAND.md at the repo root.
 */

export const BRAND = {
  violet: "#5B2A86",
  cyan: "#22D3EE",
  offWhite: "#FAFAFA",
  nearBlack: "#0B0B0F",
  amber: "#FB923C",

  // Neutrals derived from nearBlack, tuned for dark-mode card surfaces.
  surface: "#14141A",
  surfaceRaised: "#1C1C24",
  border: "#2A2A33",
  borderStrong: "#3A3A44",

  // Muted text that passes WCAG AA on nearBlack bg (~6:1 contrast).
  muted: "#9CA3AF",
  subtle: "#6B7280",
} as const;

/**
 * Severity color system. Shared between html-reporter and dashboard-html so
 * critical/high/medium/low render identically across both surfaces.
 *
 * Hybrid approach: semantic red/emerald preserved for user familiarity,
 * brand amber + cyan wired as high/low. All values contrast ≥4.5:1 on BRAND.nearBlack.
 */
export const SEVERITY_HEX = {
  critical: "#EF4444",
  high: BRAND.amber,
  medium: "#F59E0B",
  low: BRAND.cyan,
  verified: "#10B981",
  dismissed: BRAND.muted,
} as const;

export type SeverityKey = keyof typeof SEVERITY_HEX;
