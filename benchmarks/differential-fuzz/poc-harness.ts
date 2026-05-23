/**
 * Reusable PoC harness for the validate-vs-fetch SSRF-bypass primitive
 * documented in docs/research/2026-05-23-differential-fuzz-first-run.md.
 *
 * Six confirmed-divergent inputs are fed through:
 *   - the package's validator (callback you pass in)
 *   - the canonical hostname that fetch()/http.get() would resolve to
 *
 * If the validator says "OK" while the canonical hostname is a private/
 * loopback address, the package is exploitable. The harness reports each
 * input's verdict as one of:
 *
 *   PASS    — validator rejected (correct behavior)
 *   BYPASS  — validator accepted, fetch would route to loopback / private
 *   ERROR   — validator threw (informative: how it fails on weird input)
 *
 * Usage from a one-off test script:
 *
 *   import { runPocHarness } from "./poc-harness.js";
 *   import { isAllowed } from "<the-target-package>";
 *
 *   await runPocHarness({
 *     name: "target-package@1.2.3",
 *     // Return true if the package would let the URL through.
 *     validator: (url) => isAllowed(url),
 *   });
 *
 * Optionally pass `fetcher` if the package wraps fetch with its own
 * normalization step — then we can detect rarer split-brain patterns.
 */

export interface PocInput {
  /** The malicious URL. */
  url: string;
  /** What `url.parse(url).hostname` returns (the literal). */
  legacyHostname: string;
  /** What `new URL(url).hostname` returns (the canonical). */
  canonicalHostname: string;
  /** Short description of which primitive this exercises. */
  primitive: string;
}

export const POC_INPUTS: readonly PocInput[] = [
  {
    url: "http://0x7f000001/",
    legacyHostname: "0x7f000001",
    canonicalHostname: "127.0.0.1",
    primitive: "IPv4 hex literal",
  },
  {
    url: "http://2130706433/",
    legacyHostname: "2130706433",
    canonicalHostname: "127.0.0.1",
    primitive: "IPv4 dotless decimal",
  },
  {
    url: "http://0177.0.0.1/",
    legacyHostname: "0177.0.0.1",
    canonicalHostname: "127.0.0.1",
    primitive: "IPv4 octal first octet",
  },
  {
    url: "http://127.1/",
    legacyHostname: "127.1",
    canonicalHostname: "127.0.0.1",
    primitive: "IPv4 shorthand",
  },
  {
    url: "http://[::ffff:127.0.0.1]/",
    legacyHostname: "::ffff:127.0.0.1",
    canonicalHostname: "[::ffff:7f00:1]",
    primitive: "IPv6-mapped IPv4 loopback",
  },
  {
    url: "http://ｅｖｉｌ.com/",
    legacyHostname: "evil.com",
    canonicalHostname: "evil.com",
    primitive: "IDN fullwidth homoglyph (parser-dependent normalization)",
  },
] as const;

export interface PocOptions {
  /** Human-readable name for the package under test. */
  name: string;
  /**
   * The validator under test. Return `true` if the package would allow
   * the URL through to the network layer. May be sync or async. May throw.
   */
  validator: (url: string) => boolean | Promise<boolean>;
  /**
   * Optional: if the package transforms the URL before fetching (e.g.
   * canonicalizes the hostname itself), pass the transform so we can
   * detect post-validation reshape attacks. If omitted, we use Node's
   * `new URL(...).hostname` as the canonical answer.
   */
  fetcher?: (url: string) => string | Promise<string>;
}

export interface PocVerdict {
  primitive: string;
  url: string;
  validatorSaid: boolean | "ERROR";
  canonicalHost: string;
  verdict: "PASS" | "BYPASS" | "ERROR" | "INFO";
  note?: string;
}

const PRIVATE_HOST_TOKENS = [
  "127.",
  "0.0.0.0",
  "localhost",
  "169.254.",
  "10.",
  "172.16.",
  "172.17.",
  "172.18.",
  "172.19.",
  "172.20.",
  "172.21.",
  "172.22.",
  "172.23.",
  "172.24.",
  "172.25.",
  "172.26.",
  "172.27.",
  "172.28.",
  "172.29.",
  "172.30.",
  "172.31.",
  "192.168.",
  "::1",
  "fe80:",
  "fc00:",
  "::ffff:7f", // IPv6-mapped IPv4 loopback (any 7f00:x form)
  "::ffff:127.",
];

function isPrivateLooking(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return PRIVATE_HOST_TOKENS.some((tok) => lower.includes(tok));
}

export async function runPocHarness(opts: PocOptions): Promise<PocVerdict[]> {
  const verdicts: PocVerdict[] = [];
  for (const input of POC_INPUTS) {
    let validatorSaid: boolean | "ERROR";
    try {
      validatorSaid = await opts.validator(input.url);
    } catch {
      validatorSaid = "ERROR";
    }

    let canonical: string;
    if (opts.fetcher) {
      try {
        canonical = await opts.fetcher(input.url);
      } catch {
        canonical = input.canonicalHostname;
      }
    } else {
      try {
        canonical = new URL(input.url).hostname;
      } catch {
        canonical = input.canonicalHostname;
      }
    }

    let verdict: PocVerdict["verdict"];
    let note: string | undefined;
    if (validatorSaid === "ERROR") {
      verdict = "ERROR";
    } else if (validatorSaid === true && isPrivateLooking(canonical)) {
      verdict = "BYPASS";
      note = `validator allowed; fetch would resolve to ${canonical}`;
    } else if (validatorSaid === false) {
      verdict = "PASS";
    } else {
      verdict = "INFO";
      note = `validator allowed but canonical (${canonical}) is not obviously private`;
    }

    verdicts.push({
      primitive: input.primitive,
      url: input.url,
      validatorSaid,
      canonicalHost: canonical,
      verdict,
      note,
    });
  }

  const w = (s: string, n: number): string => s.length >= n ? s : s + " ".repeat(n - s.length);
  console.log(`\n=== PoC: ${opts.name} ===`);
  console.log(w("primitive", 42) + w("verdict", 8) + w("validator", 12) + "canonical");
  console.log("-".repeat(90));
  for (const v of verdicts) {
    console.log(
      w(v.primitive, 42) +
        w(v.verdict, 8) +
        w(String(v.validatorSaid), 12) +
        v.canonicalHost
    );
    if (v.note) console.log("  " + v.note);
  }
  const bypasses = verdicts.filter((v) => v.verdict === "BYPASS");
  console.log("-".repeat(90));
  console.log(`bypasses: ${bypasses.length} / ${verdicts.length}`);
  return verdicts;
}
