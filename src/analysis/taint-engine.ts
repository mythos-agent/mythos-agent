import fs from "node:fs";
import path from "node:path";
import type { CodebaseMap, FunctionDef, RouteDef } from "./code-parser.js";
import type { CallGraph } from "./call-graph.js";
import type { Vulnerability, Severity } from "../types/index.js";

/**
 * Taint sources — where user-controlled data enters the application.
 */
const TAINT_SOURCES: Record<string, RegExp[]> = {
  "http-param": [
    /req\.query\.\w+/g,
    /req\.params\.\w+/g,
    /req\.body\.\w+/g,
    /req\.body$/gm,
    /req\.headers\.\w+/g,
    /req\.cookies\.\w+/g,
    /request\.args/g,
    /request\.form/g,
    /request\.json/g,
    /request\.GET/g,
    /request\.POST/g,
    /r\.URL\.Query\(\)/g,
    /r\.FormValue\(/g,
    /\$_GET\[/g,
    /\$_POST\[/g,
    /\$_REQUEST\[/g,
    /\$_COOKIE\[/g,
  ],
  "url-input": [
    /window\.location/g,
    /document\.location/g,
    /document\.URL/g,
    /document\.referrer/g,
  ],
  "user-input": [
    /process\.argv/g,
    /process\.stdin/g,
    /readline/g,
    /sys\.argv/g,
    /os\.Args/g,
  ],
  "file-input": [
    /fs\.readFileSync\(/g,
    /fs\.readFile\(/g,
    /open\(\s*(?:req|request|params|input)/g,
  ],
};

/**
 * Taint sinks — dangerous operations that should not receive unsanitized input.
 */
const TAINT_SINKS: Record<string, { pattern: RegExp; severity: Severity; cwe: string; title: string }[]> = {
  "sql-injection": [
    { pattern: /\.query\s*\(/g, severity: "critical", cwe: "CWE-89", title: "SQL Injection Sink" },
    { pattern: /\.execute\s*\(/g, severity: "critical", cwe: "CWE-89", title: "SQL Execution Sink" },
    { pattern: /\.raw\s*\(/g, severity: "critical", cwe: "CWE-89", title: "Raw SQL Sink" },
  ],
  "command-injection": [
    { pattern: /exec\s*\(/g, severity: "critical", cwe: "CWE-78", title: "Command Execution Sink" },
    { pattern: /execSync\s*\(/g, severity: "critical", cwe: "CWE-78", title: "Sync Command Execution Sink" },
    { pattern: /spawn\s*\(/g, severity: "high", cwe: "CWE-78", title: "Process Spawn Sink" },
    { pattern: /child_process/g, severity: "critical", cwe: "CWE-78", title: "Child Process Sink" },
    { pattern: /os\.system\s*\(/g, severity: "critical", cwe: "CWE-78", title: "OS System Call Sink" },
    { pattern: /subprocess/g, severity: "critical", cwe: "CWE-78", title: "Subprocess Sink" },
  ],
  "xss": [
    { pattern: /innerHTML\s*=/g, severity: "high", cwe: "CWE-79", title: "innerHTML Assignment Sink" },
    { pattern: /dangerouslySetInnerHTML/g, severity: "high", cwe: "CWE-79", title: "React Unsafe HTML Sink" },
    { pattern: /document\.write\s*\(/g, severity: "high", cwe: "CWE-79", title: "Document Write Sink" },
    { pattern: /\.html\s*\(/g, severity: "medium", cwe: "CWE-79", title: "HTML Render Sink" },
  ],
  "path-traversal": [
    { pattern: /readFileSync\s*\(/g, severity: "high", cwe: "CWE-22", title: "File Read Sink" },
    { pattern: /writeFileSync\s*\(/g, severity: "high", cwe: "CWE-22", title: "File Write Sink" },
    { pattern: /createReadStream\s*\(/g, severity: "high", cwe: "CWE-22", title: "Read Stream Sink" },
    { pattern: /path\.join\s*\(/g, severity: "medium", cwe: "CWE-22", title: "Path Join (potential sink)" },
  ],
  "ssrf": [
    { pattern: /fetch\s*\(/g, severity: "high", cwe: "CWE-918", title: "HTTP Fetch Sink" },
    { pattern: /axios\s*[.(]/g, severity: "high", cwe: "CWE-918", title: "Axios Request Sink" },
    { pattern: /http\.get\s*\(/g, severity: "high", cwe: "CWE-918", title: "HTTP Get Sink" },
    { pattern: /requests\.get\s*\(/g, severity: "high", cwe: "CWE-918", title: "Python Requests Sink" },
  ],
  "eval": [
    { pattern: /\beval\s*\(/g, severity: "critical", cwe: "CWE-95", title: "Eval Sink" },
    { pattern: /new\s+Function\s*\(/g, severity: "critical", cwe: "CWE-95", title: "Dynamic Function Sink" },
  ],
  "redirect": [
    { pattern: /\.redirect\s*\(/g, severity: "medium", cwe: "CWE-601", title: "Redirect Sink" },
    { pattern: /location\s*=/g, severity: "medium", cwe: "CWE-601", title: "Location Assignment Sink" },
  ],
};

/**
 * Known sanitizers that break taint propagation.
 */
const SANITIZERS = [
  /escape\w*/i,
  /sanitize\w*/i,
  /encode\w*/i,
  /htmlspecialchars/i,
  /htmlentities/i,
  /encodeURI/i,
  /encodeURIComponent/i,
  /DOMPurify/i,
  /validator\.\w+/i,
  /parseInt\s*\(/i,
  /Number\s*\(/i,
  /parameterized/i,
  /prepared/i,
  /placeholder/i,
];

export interface TaintFlow {
  id: string;
  source: {
    type: string;
    file: string;
    line: number;
    code: string;
  };
  sink: {
    type: string;
    file: string;
    line: number;
    code: string;
    severity: Severity;
    cwe: string;
    title: string;
  };
  hops: Array<{
    file: string;
    line: number;
    code: string;
    description: string;
  }>;
  sanitized: boolean;
  sanitizer?: string;
}

/**
 * Run deterministic taint analysis across the codebase.
 * Traces user input from sources to dangerous sinks.
 */
export function runTaintAnalysis(
  codebaseMap: CodebaseMap,
  callGraph: CallGraph,
  projectPath: string
): TaintFlow[] {
  const flows: TaintFlow[] = [];
  let flowId = 1;

  // For each route handler, trace taint from sources to sinks
  for (const route of codebaseMap.routes) {
    const absPath = path.resolve(projectPath, route.file);
    if (!fs.existsSync(absPath)) continue;

    const content = fs.readFileSync(absPath, "utf-8");
    const lines = content.split("\n");

    // Find handler function body
    const handlerStart = route.line - 1;
    const handlerEnd = findHandlerEnd(lines, handlerStart);
    const handlerBody = lines.slice(handlerStart, handlerEnd);

    // Find sources in handler
    const sources = findSources(handlerBody, route.file, handlerStart);

    // Find sinks in handler
    const sinks = findSinks(handlerBody, route.file, handlerStart);

    // For each source-sink pair, check if there's an unsanitized path
    for (const source of sources) {
      for (const sink of sinks) {
        // Check if any sanitizer exists between source and sink
        const bodyBetween = lines.slice(
          Math.min(source.line - 1, handlerStart),
          Math.max(sink.line, handlerEnd)
        ).join("\n");

        const sanitizer = SANITIZERS.find((s) => s.test(bodyBetween));
        const sanitized = !!sanitizer;

        flows.push({
          id: `TAINT-${String(flowId++).padStart(3, "0")}`,
          source: {
            type: source.type,
            file: route.file,
            line: source.line,
            code: source.code,
          },
          sink: {
            type: sink.category,
            file: route.file,
            line: sink.line,
            code: sink.code,
            severity: sink.severity,
            cwe: sink.cwe,
            title: sink.title,
          },
          hops: [],
          sanitized,
          sanitizer: sanitizer?.source,
        });
      }
    }
  }

  // Also trace cross-file taint via call graph
  for (const func of codebaseMap.functions) {
    const absPath = path.resolve(projectPath, func.file);
    if (!fs.existsSync(absPath)) continue;

    const content = fs.readFileSync(absPath, "utf-8");
    const funcLines = content.split("\n").slice(func.line - 1, func.endLine);
    const funcBody = funcLines.join("\n");

    // If function has taint sources in params AND its callers pass user input
    if (func.params.some((p) => /req|request|input|data|body|query|params/i.test(p))) {
      const sinks = findSinks(funcLines, func.file, func.line - 1);
      if (sinks.length > 0) {
        // Check who calls this function
        const callerKey = `${func.file}:${func.name}`;
        const callers = callGraph.callers.get(callerKey) || [];

        for (const caller of callers) {
          for (const sink of sinks) {
            const sanitizer = SANITIZERS.find((s) => s.test(funcBody));
            flows.push({
              id: `TAINT-${String(flowId++).padStart(3, "0")}`,
              source: {
                type: "function-param",
                file: caller.file,
                line: caller.line,
                code: `${caller.caller} → ${func.name}(...)`,
              },
              sink: {
                type: sink.category,
                file: func.file,
                line: sink.line,
                code: sink.code,
                severity: sink.severity,
                cwe: sink.cwe,
                title: sink.title,
              },
              hops: [{
                file: func.file,
                line: func.line,
                code: `function ${func.name}(${func.params.join(", ")})`,
                description: `Data passed through ${func.name}`,
              }],
              sanitized: !!sanitizer,
              sanitizer: sanitizer?.source,
            });
          }
        }
      }
    }
  }

  return flows;
}

/**
 * Convert taint flows to vulnerability findings.
 * Only unsanitized flows become findings.
 */
export function taintFlowsToVulnerabilities(flows: TaintFlow[]): Vulnerability[] {
  return flows
    .filter((f) => !f.sanitized)
    .map((f) => ({
      id: f.id,
      rule: `taint:${f.sink.type}`,
      title: `${f.sink.title}: ${f.source.type} → ${f.sink.type}`,
      description: `User input from ${f.source.type} at ${f.source.file}:${f.source.line} flows to ${f.sink.title.toLowerCase()} at ${f.sink.file}:${f.sink.line} without sanitization.`,
      severity: f.sink.severity,
      category: f.sink.type.split("-")[0] || "taint",
      cwe: f.sink.cwe,
      confidence: "high" as const,
      location: {
        file: f.sink.file,
        line: f.sink.line,
        snippet: f.sink.code,
      },
    }));
}

interface SourceMatch {
  type: string;
  line: number;
  code: string;
}

interface SinkMatch {
  category: string;
  line: number;
  code: string;
  severity: Severity;
  cwe: string;
  title: string;
}

function findSources(lines: string[], file: string, offset: number): SourceMatch[] {
  const sources: SourceMatch[] = [];
  for (let i = 0; i < lines.length; i++) {
    for (const [type, patterns] of Object.entries(TAINT_SOURCES)) {
      for (const pattern of patterns) {
        pattern.lastIndex = 0;
        if (pattern.test(lines[i])) {
          sources.push({
            type,
            line: offset + i + 1,
            code: lines[i].trim(),
          });
        }
      }
    }
  }
  return sources;
}

function findSinks(lines: string[], file: string, offset: number): SinkMatch[] {
  const sinks: SinkMatch[] = [];
  for (let i = 0; i < lines.length; i++) {
    for (const [category, sinkDefs] of Object.entries(TAINT_SINKS)) {
      for (const sink of sinkDefs) {
        sink.pattern.lastIndex = 0;
        if (sink.pattern.test(lines[i])) {
          sinks.push({
            category,
            line: offset + i + 1,
            code: lines[i].trim(),
            severity: sink.severity,
            cwe: sink.cwe,
            title: sink.title,
          });
        }
      }
    }
  }
  return sinks;
}

function findHandlerEnd(lines: string[], start: number): number {
  let depth = 0;
  let started = false;
  for (let i = start; i < lines.length && i < start + 200; i++) {
    for (const ch of lines[i]) {
      if (ch === "{") { depth++; started = true; }
      if (ch === "}") depth--;
    }
    if (started && depth === 0) return i + 1;
  }
  return Math.min(start + 50, lines.length);
}
