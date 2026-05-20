import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

type Confidence = "high" | "medium" | "low";

const DESER_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
  /**
   * Per-rule confidence override. When absent the scanner defaults to "high".
   * Rules with known false-positive sources (e.g. single-line window scan that
   * can miss nearby mitigations) must set this to "medium" or "low".
   */
  confidence?: Confidence;
  /**
   * Optional post-match mitigation check. Called after a pattern fires.
   * Receives the file's lines array and the 1-based line number of the match.
   * Return true when a mitigation is detected — suppresses the finding.
   * Use this instead of negative lookaheads to avoid missing next-line guards.
   */
  mitigationCheck?: (lines: string[], lineNum: number) => boolean;
}> = [
  {
    id: "deser-json-parse-untrusted",
    title: "Deserialization: JSON.parse on Untrusted Input",
    description:
      "JSON.parse on user input without try/catch. Malformed JSON crashes the process. Also check for __proto__ pollution.",
    severity: "medium",
    cwe: "CWE-502",
    // Confidence is "medium" — even with the window check below, a try/catch
    // wrapping JSON.parse might exist outside the 5-line scan window (e.g. a
    // top-level handler). Avoid a "high" false-positive storm.
    confidence: "medium",
    // Removed (?![\s\S]{0,50}catch) — that lookahead only scanned the current
    // line and missed try/catch blocks that wrap the call on adjacent lines.
    // The mitigationCheck below inspects a 5-line window instead.
    patterns: [/JSON\.parse\s*\(\s*(?:req\.body|req\.query|data|input|message|payload)/gi],
    mitigationCheck(lines: string[], lineNum: number): boolean {
      // Look back 2 lines (for `try {` on the line before) and forward 2 lines
      // (for `} catch` on the lines after) — total window of 5 lines including
      // the match line itself.
      const window = lines.slice(Math.max(0, lineNum - 3), lineNum - 1 + 3).join("\n");
      return window.includes("catch");
    },
  },
  {
    id: "deser-pickle-loads",
    title: "Deserialization: pickle.loads on Untrusted Data",
    description:
      "Python pickle deserialization executes arbitrary code. Never unpickle untrusted data. Use JSON instead.",
    severity: "critical",
    cwe: "CWE-502",
    patterns: [/pickle\.loads?\s*\(/gi, /cPickle\.loads?\s*\(/gi, /shelve\.open\s*\(/gi],
  },
  {
    id: "deser-yaml-unsafe",
    title: "Deserialization: Unsafe YAML Loading",
    description:
      "yaml.load() without SafeLoader executes arbitrary Python code. Use yaml.safe_load() instead.",
    severity: "critical",
    cwe: "CWE-502",
    patterns: [
      /yaml\.load\s*\((?!.*(?:SafeLoader|safe_load|Loader=yaml\.SafeLoader))/gi,
      /yaml\.unsafe_load\s*\(/gi,
    ],
  },
  {
    id: "deser-xml-xxe",
    title: "Deserialization: XML Parser Vulnerable to XXE",
    description:
      "XML parser without disabled external entities. Enables file read, SSRF, and DoS via XML External Entities.",
    severity: "high",
    cwe: "CWE-611",
    patterns: [
      /(?:parseString|parseXML|DOMParser|SAXParser|XMLReader)(?![\s\S]{0,200}(?:disallow|external|noent|resolve_entities.*False))/gi,
      /etree\.parse\s*\(/gi,
      /xml2js\.parseString\s*\(/gi,
    ],
  },
  {
    id: "deser-java-objectinput",
    title: "Deserialization: Java ObjectInputStream",
    description:
      "Java deserialization via ObjectInputStream enables arbitrary code execution with crafted payloads.",
    severity: "critical",
    cwe: "CWE-502",
    patterns: [/ObjectInputStream\s*\(/gi, /\.readObject\s*\(\s*\)/gi, /readUnshared\s*\(\s*\)/gi],
  },
  {
    id: "deser-proto-pollution",
    title: "Deserialization: Prototype Pollution via Deep Merge",
    description:
      "Deep merge/clone of user input can pollute Object.prototype via __proto__ or constructor properties.",
    severity: "high",
    cwe: "CWE-1321",
    patterns: [
      /(?:merge|deepMerge|extend|assign|defaults)\s*\(.*(?:req\.body|req\.query|input|data|payload)/gi,
      /(?:lodash|_)\.(?:merge|defaultsDeep|set)\s*\(.*(?:req\.|input|data)/gi,
    ],
  },
  {
    id: "deser-eval-json",
    title: "Deserialization: eval() Used to Parse Data",
    description:
      "eval() used to parse JSON or data. Use JSON.parse() instead — eval executes arbitrary code.",
    severity: "critical",
    cwe: "CWE-95",
    patterns: [/eval\s*\(\s*['"]?\s*\(\s*['"]?\s*(?:data|json|response|input|payload)/gi],
  },
];

export interface DeserializationScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class DeserializationScanner {
  async scan(projectPath: string): Promise<DeserializationScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py", "**/*.java"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
      nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try {
        const s = fs.statSync(file);
        if (s.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of DESER_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              // Bounded-window mitigation check (replaces single-line negative
              // lookaheads that could not see mitigations on adjacent lines).
              if (rule.mitigationCheck && rule.mitigationCheck(lines, i + 1)) continue;
              findings.push({
                id: `DESER-${String(id++).padStart(4, "0")}`,
                rule: `deser:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "deserialization",
                cwe: rule.cwe,
                confidence: rule.confidence ?? "high",
                location: { file: rel, line: i + 1, snippet: lines[i].trim() },
              });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
