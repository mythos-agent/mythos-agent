import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SEED_PATTERNS, getSeedPattern } from "../seed-patterns.js";
import { findAstPattern } from "../../ast-matcher/index.js";
import type { RootCausePattern } from "../types.js";

// ---------------------------------------------------------------------------
// Seed-corpus expansion test (Task 6 of the tier-0 quick-wins plan).
//
// The variant seed corpus grew from 5 (the CVE Replay calibration cases)
// to 11 with the addition of 6 bug-class-coverage seeds. This file pins:
//
//  (a) the seed count and the iteration order of the new entries,
//  (b) that each new CVE/GHSA id resolves through getSeedPattern, and
//  (c) the acceptance gate: each new seed's `astShape` MUST actually
//      match its hand-written fixture. The fixture is a small snippet
//      of vulnerable-shaped code modeled on the real fix commit; if
//      findAstPattern returns no match the seed's `astShape.kind` is
//      wrong (the test is the gate — do NOT weaken it to pass).
//
// The 6 new seeds are intentionally NOT paired with CVE Replay case
// files, so root-cause.test.ts's "seed has a matching case" assertion
// is scoped to the original 5 corpus seeds (see CALIBRATION_CVES there).
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(__dirname, "fixtures");

/** The 6 Tier-2 seeds added in Task 6, paired with their fixture slug. */
const NEW_SEEDS: ReadonlyArray<{ cveId: string; ghsaId: string; fixture: string }> = [
  { cveId: "CVE-2019-10744", ghsaId: "GHSA-jf85-cpcp-j695", fixture: "prototype-pollution" },
  { cveId: "CVE-2021-21315", ghsaId: "GHSA-2m8v-572m-ff2v", fixture: "os-command-injection" },
  { cveId: "CVE-2018-1002204", ghsaId: "GHSA-3v6h-hqm4-2rg6", fixture: "path-traversal" },
  { cveId: "CVE-2020-28168", ghsaId: "GHSA-4w2v-q235-vp99", fixture: "ssrf" },
  { cveId: "CVE-2019-10752", ghsaId: "GHSA-m9jw-237r-gvfv", fixture: "sql-injection" },
  { cveId: "CVE-2022-39353", ghsaId: "GHSA-crh6-fp67-6883", fixture: "xxe" },
];

describe("seed corpus — expanded to 11 seeds", () => {
  it("has exactly 11 seed patterns", () => {
    expect(SEED_PATTERNS.length).toBe(11);
  });

  it("resolves each of the 6 new seeds by CVE id", () => {
    for (const { cveId } of NEW_SEEDS) {
      const seed = getSeedPattern(cveId);
      expect(seed, `getSeedPattern(${cveId}) should resolve`).not.toBeNull();
      expect(seed?.cveId).toBe(cveId);
    }
  });

  it("resolves each of the 6 new seeds by GHSA id (same object as CVE lookup)", () => {
    for (const { cveId, ghsaId } of NEW_SEEDS) {
      const byGhsa = getSeedPattern(ghsaId);
      const byCve = getSeedPattern(cveId);
      expect(byGhsa, `getSeedPattern(${ghsaId}) should resolve`).not.toBeNull();
      expect(byGhsa).toBe(byCve);
    }
  });

  it("gives every new seed a distinct bugClass", () => {
    const bugClasses = NEW_SEEDS.map((s) => getSeedPattern(s.cveId)?.bugClass);
    expect(new Set(bugClasses).size).toBe(NEW_SEEDS.length);
  });
});

describe("seed corpus — offline matcher acceptance gate", () => {
  // For each new seed, parse its fixture with A2's matcher driven by
  // the seed's own `astShape.kind` and assert at least one match. This
  // is the exact composition the calibration runner uses (see
  // src/analysis/calibration/runner.ts): kind + source + language.
  it.each(NEW_SEEDS.map((s) => [s.cveId, s] as const))(
    "%s — astShape matches its fixture",
    async (_cveId, { cveId, fixture }) => {
      const seed = getSeedPattern(cveId) as RootCausePattern;
      expect(seed).not.toBeNull();

      const source = fs.readFileSync(path.join(FIXTURES, `${fixture}.txt`), "utf-8");
      const matches = await findAstPattern({
        kind: seed.astShape.kind,
        source,
        language: "javascript",
      });

      expect(
        matches.length,
        `seed ${cveId} (kind: ${seed.astShape.kind}) found no match in fixture ${fixture}.txt`
      ).toBeGreaterThan(0);
    }
  );
});
