import type { CorpusEntry } from "./corpus.js";

/** Deterministic PRNG (mulberry32) — a fixed seed yields a fixed sequence. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CONFUSION_CHARS = [
  "@",
  "\\",
  "/",
  "#",
  "?",
  ":",
  "\t",
  "\n",
  "\r",
  " ",
  "\u00a0",
  "\u3000",
  "\u3002",
  "\uff0e",
  "%2f",
  "%00",
];

function flipCase(ch: string): string {
  const lower = ch.toLowerCase();
  return ch === lower ? ch.toUpperCase() : lower;
}

function applyMutation(url: string, rand: () => number, pick: <T>(a: T[]) => T): string {
  const op = Math.floor(rand() * 5);
  const pos = Math.floor(rand() * (url.length + 1));
  switch (op) {
    case 0: // insert a confusion char
      return url.slice(0, pos) + pick(CONFUSION_CHARS) + url.slice(pos);
    case 1: // duplicate the char at pos
      return pos < url.length ? url.slice(0, pos) + url[pos] + url.slice(pos) : url;
    case 2: // delete the char at pos
      return pos < url.length ? url.slice(0, pos) + url.slice(pos + 1) : url;
    case 3: // flip case at pos
      return pos < url.length ? url.slice(0, pos) + flipCase(url[pos]) + url.slice(pos + 1) : url;
    default: // append two confusion chars
      return url + pick(CONFUSION_CHARS) + pick(CONFUSION_CHARS);
  }
}

/**
 * Expand the corpus into `count` fuzzing inputs. Intended for
 * `count >= seeds.length` — the raw seed URLs come first, then the
 * remainder are produced by applying 1-3 random mutations to a
 * randomly-picked seed. When `count < seeds.length` only the first
 * `count` seed URLs are returned (no mutations). Fully deterministic
 * given `(seeds, count, seed)`.
 */
export function mutate(seeds: CorpusEntry[], count: number, seed: number): string[] {
  const rand = mulberry32(seed);
  const pick = <T>(arr: T[]): T => arr[Math.floor(rand() * arr.length)];
  const out: string[] = seeds.map((s) => s.url);
  while (out.length < count) {
    let url = pick(seeds).url;
    const ops = 1 + Math.floor(rand() * 3);
    for (let i = 0; i < ops; i++) url = applyMutation(url, rand, pick);
    out.push(url);
  }
  return out.slice(0, count);
}
