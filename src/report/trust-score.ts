import type { Vulnerability, VulnChain, Severity } from "../types/index.js";

/**
 * Per-finding deduction from the base score of 10.
 *
 * - critical: −2.0
 * - high:     −1.0
 * - medium:   −0.5
 * - low:      −0.2
 * - info:     −0.0  (informational findings do not affect trust)
 */
const FINDING_PENALTY: Record<Severity, number> = {
  critical: 2.0,
  high: 1.0,
  medium: 0.5,
  low: 0.2,
  info: 0,
};

/**
 * Per-chain (attack-chain) deduction on top of individual finding penalties.
 * Chains represent multi-step exploitation paths and carry extra weight.
 *
 * - critical: −1.5
 * - high:     −1.0
 * - medium:   −0.5
 * - low:      −0.0  (low-severity and info chains carry no extra penalty)
 * - info:     −0.0
 */
const CHAIN_PENALTY: Record<Severity, number> = {
  critical: 1.5,
  high: 1.0,
  medium: 0.5,
  low: 0,
  info: 0,
};

/**
 * Compute the trust score for a set of confirmed vulnerabilities and attack chains.
 *
 * Formula:
 *   score = 10
 *         − Σ FINDING_PENALTY[v.severity]  for each confirmed vulnerability v
 *         − Σ CHAIN_PENALTY[c.severity]    for each attack chain c
 *   score = clamp(score, 0, 10)
 *
 * The result is a floating-point number in [0, 10]; callers are responsible
 * for any display rounding (e.g. `.toFixed(1)`).
 *
 * @param vulns  Confirmed vulnerabilities from the scan.
 * @param chains Attack chains identified by the scan (pass `undefined` or `[]`
 *               when none are present — e.g. when only vulnerability counts are
 *               available without chain data).
 * @returns Trust score in the range [0, 10].
 */
export function calculateTrustScore(
  vulns: Vulnerability[],
  chains: VulnChain[] | undefined
): number {
  let score = 10;

  for (const v of vulns) {
    score -= FINDING_PENALTY[v.severity] ?? 0;
  }

  if (chains) {
    for (const c of chains) {
      score -= CHAIN_PENALTY[c.severity] ?? 0;
    }
  }

  return Math.max(0, Math.min(10, score));
}
