import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const DESER_RULES: Array<{ id: string; title: string; description: string; severity: Severity; cwe: string; patterns: RegExp[] }> = [
  {
    id: "deser-json-parse-untrusted",
    title: "Deserialization: JSON.parse on Untrusted Input",
    description: "JSON.parse on user input without try/catch. Malformed JSON crashes the process. Also check for __proto__ pollution.",
    severity: "medium",
    cwe: "CWE-502",
    patterns: [
      /JSON\.parse\s*\(\s*(?:req\.body|req\.query|data|input|message|payload)(?![\s\S]{0,50}catch)/gi,
    ],
  },
  {
    id: "deser-pickle-loads",
    title: "Deserialization: pickle.loads on Untrusted Data",
    description: "Python pickle deserialization executes arbitrary code. Never unpickle untrusted data. Use JSON instead.",
    severity: "critical",
    cwe: "CWE-502",
    patterns: [
      /pickle\.loads?\s*\(/gi,
      /cPickle\.loads?\s*\(/gi,
      /shelve\.open\s*\(/gi,
    ],
  },
  {
    id: "deser-yaml-unsafe",
    title: "Deserialization: Unsafe YAML Loading",
    description: "yaml.load() without SafeLoader executes arbitrary Python code. Use yaml.safe_load() instead.",
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
    description: "XML parser without disabled external entities. Enables file read, SSRF, and DoS via XML External Entities.",
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
    description: "Java deserialization via ObjectInputStream enables arbitrary code execution with crafted payloads.",
    severity: "critical",
    cwe: "CWE-502",
    patterns: [
      /ObjectInputStream\s*\(/gi,
      /\.readObject\s*\(\s*\)/gi,
      /readUnshared\s*\(\s*\)/gi,
    ],
  },
  {
    id: "deser-proto-pollution",
    title: "Deserialization: Prototype Pollution via Deep Merge",
    description: "Deep merge/clone of user input can pollute Object.prototype via __proto__ or constructor properties.",
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
    description: "eval() used to parse JSON or data. Use JSON.parse() instead — eval executes arbitrary code.",
    severity: "critical",
    cwe: "CWE-95",
    patterns: [
      /eval\s*\(\s*['"]?\s*\(\s*['"]?\s*(?:data|json|response|input|payload)/gi,
    ],
  },
];

export interface DeserializationScanResult { findings: Vulnerability[]; filesScanned: number; }

export class DeserializationScanner {
  async scan(projectPath: string): Promise<DeserializationScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py", "**/*.java"], {
      cwd: projectPath, absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"], nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try { const s = fs.statSync(file); if (s.size > 500_000) continue; content = fs.readFileSync(file, "utf-8"); } catch { continue; }
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of DESER_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            p.lastIndex = 0;
            if (p.test(lines[i])) {
              findings.push({ id: `DESER-${String(id++).padStart(4, "0")}`, rule: `deser:${rule.id}`, title: rule.title, description: rule.description, severity: rule.severity, category: "deserialization", cwe: rule.cwe, confidence: "high", location: { file: rel, line: i + 1, snippet: lines[i].trim() } });
            }
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
