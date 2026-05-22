/** The three URL parsers under differential test. */
export type ParserId = "native-url" | "url-parse" | "legacy-url";

/** Security-relevant URL components compared across parsers. */
export type DivergenceField =
  | "protocol"
  | "hostname"
  | "port"
  | "username"
  | "password"
  | "pathname";

/** Normalized output of one parser for one input. */
export interface ParserResult {
  protocol?: string;
  hostname?: string;
  port?: string;
  username?: string;
  password?: string;
  pathname?: string;
  /** Set when the parser threw on this input. */
  error?: string;
  /** Set when the parse exceeded the worker timeout. */
  hang?: true;
}

export type DivergenceKind = "field" | "throw" | "hang";

/** A single pairwise disagreement on one input. */
export interface Divergence {
  input: string;
  kind: DivergenceKind;
  /** Present when kind === "field". */
  field?: DivergenceField;
  parserA: ParserId;
  parserB: ParserId;
  valueA: string | undefined;
  valueB: string | undefined;
  /** Dedup key — structurally identical divergences share a signature. */
  signature: string;
}

export type TriageCategory = "spec-ambiguity" | "likely-exploitable" | "dos";

/** A deduped group of structurally-identical divergences. */
export interface DivergenceClass {
  signature: string;
  kind: DivergenceKind;
  field?: DivergenceField;
  parserA: ParserId;
  parserB: ParserId;
  /** One representative input from the class. */
  representativeInput: string;
  /** How many fuzzed inputs produced this divergence. */
  count: number;
}

/** A DivergenceClass after LLM triage. */
export interface TriagedDivergenceClass extends DivergenceClass {
  /** Undefined when triage failed for this class. */
  category?: TriageCategory;
  rationale?: string;
}

/** Severity rank of a field — higher sorts first in the report. */
export const FIELD_SEVERITY: Record<DivergenceField, number> = {
  hostname: 5,
  protocol: 5,
  port: 3,
  username: 2,
  password: 2,
  pathname: 1,
};

export interface FuzzReport {
  generatedAt: string;
  seed: number;
  corpusSize: number;
  inputsTested: number;
  classes: TriagedDivergenceClass[];
}
