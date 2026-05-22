import type {
  ParserId,
  ParserResult,
  Divergence,
  DivergenceClass,
  DivergenceField,
} from "./types.js";

const PARSER_IDS: ParserId[] = ["native-url", "url-parse", "legacy-url"];
const FIELDS: DivergenceField[] = [
  "protocol",
  "hostname",
  "port",
  "username",
  "password",
  "pathname",
];

/**
 * Structural skeleton of a value: letters/digits collapsed to placeholders,
 * special characters kept. Two values with the same skeleton are treated as
 * the same *kind* of divergence for dedup. `undefined` -> the sentinel "EMPTY".
 */
function skeleton(v: string | undefined): string {
  if (v === undefined) return "EMPTY";
  return v.replace(/[a-z]/g, "a").replace(/[A-Z]/g, "A").replace(/[0-9]/g, "0");
}

function mkDivergence(
  input: string,
  kind: Divergence["kind"],
  field: DivergenceField | undefined,
  a: ParserId,
  b: ParserId,
  va: string | undefined,
  vb: string | undefined
): Divergence {
  const signature = `${kind}:${field ?? "-"}:${a}|${b}:${skeleton(va)}|${skeleton(vb)}`;
  return { input, kind, field, parserA: a, parserB: b, valueA: va, valueB: vb, signature };
}

/** Compare every parser pair for one input; emit pairwise divergences. */
export function compare(input: string, results: Record<ParserId, ParserResult>): Divergence[] {
  const out: Divergence[] = [];
  for (let i = 0; i < PARSER_IDS.length; i++) {
    for (let j = i + 1; j < PARSER_IDS.length; j++) {
      const a = PARSER_IDS[i];
      const b = PARSER_IDS[j];
      const ra = results[a];
      const rb = results[b];

      // hang divergence — one hung, the other did not
      if (Boolean(ra.hang) !== Boolean(rb.hang)) {
        out.push(
          mkDivergence(
            input,
            "hang",
            undefined,
            a,
            b,
            ra.hang ? "hang" : "ok",
            rb.hang ? "hang" : "ok"
          )
        );
        continue;
      }
      if (ra.hang && rb.hang) continue;

      // throw divergence — one threw, the other did not
      const aThrew = ra.error !== undefined;
      const bThrew = rb.error !== undefined;
      if (aThrew !== bThrew) {
        out.push(
          mkDivergence(
            input,
            "throw",
            undefined,
            a,
            b,
            aThrew ? "throw" : "ok",
            bThrew ? "throw" : "ok"
          )
        );
        continue;
      }
      if (aThrew && bThrew) continue;

      // field divergences
      for (const field of FIELDS) {
        if (ra[field] !== rb[field]) {
          out.push(mkDivergence(input, "field", field, a, b, ra[field], rb[field]));
        }
      }
    }
  }
  return out;
}

/** Deduplicate divergences by signature into counted classes. */
export function classify(divergences: Divergence[]): DivergenceClass[] {
  const map = new Map<string, DivergenceClass>();
  for (const d of divergences) {
    const existing = map.get(d.signature);
    if (existing) {
      existing.count++;
    } else {
      map.set(d.signature, {
        signature: d.signature,
        kind: d.kind,
        field: d.field,
        parserA: d.parserA,
        parserB: d.parserB,
        representativeInput: d.input,
        count: 1,
      });
    }
  }
  return [...map.values()];
}
