import fs from "node:fs";
import path from "node:path";
import type { CodebaseMap, FunctionDef } from "./code-parser.js";

export interface CallEdge {
  caller: string; // "file:functionName"
  callee: string; // "file:functionName" or "external:module.function"
  file: string;
  line: number;
}

export interface CallGraph {
  nodes: Map<string, FunctionDef>;
  edges: CallEdge[];
  callers: Map<string, CallEdge[]>; // who calls this function
  callees: Map<string, CallEdge[]>; // what does this function call
}

/**
 * Build a call graph from a parsed codebase map.
 * Resolves function calls to their definitions where possible.
 */
export function buildCallGraph(map: CodebaseMap, projectPath: string): CallGraph {
  const nodes = new Map<string, FunctionDef>();
  const edges: CallEdge[] = [];

  // Index all functions by name and file
  const funcByName = new Map<string, FunctionDef[]>();
  for (const func of map.functions) {
    const key = `${func.file}:${func.name}`;
    nodes.set(key, func);

    const existing = funcByName.get(func.name) || [];
    existing.push(func);
    funcByName.set(func.name, existing);
  }

  // Build import resolution map
  const importMap = new Map<string, Map<string, string>>(); // file -> (localName -> sourceFile)
  for (const imp of map.imports) {
    if (!importMap.has(imp.file)) importMap.set(imp.file, new Map());
    const fileImports = importMap.get(imp.file)!;
    for (const spec of imp.specifiers) {
      fileImports.set(spec, imp.source);
    }
  }

  // Scan each function body for calls to other functions
  for (const func of map.functions) {
    const absPath = path.resolve(projectPath, func.file);
    if (!fs.existsSync(absPath)) continue;

    const content = fs.readFileSync(absPath, "utf-8");
    const lines = content.split("\n");
    const funcBody = lines.slice(func.line - 1, func.endLine).join("\n");

    // Find function calls in the body
    const callPattern = /\b(\w+)\s*\(/g;
    let match;
    while ((match = callPattern.exec(funcBody)) !== null) {
      const calledName = match[1];

      // Skip common keywords
      if (isKeyword(calledName)) continue;

      // Try to resolve the call
      const resolved = resolveCall(calledName, func.file, funcByName, importMap);

      edges.push({
        caller: `${func.file}:${func.name}`,
        callee: resolved || `external:${calledName}`,
        file: func.file,
        line: func.line + funcBody.slice(0, match.index).split("\n").length - 1,
      });
    }
  }

  // Build reverse index
  const callers = new Map<string, CallEdge[]>();
  const callees = new Map<string, CallEdge[]>();

  for (const edge of edges) {
    const callerList = callees.get(edge.caller) || [];
    callerList.push(edge);
    callees.set(edge.caller, callerList);

    const calleeList = callers.get(edge.callee) || [];
    calleeList.push(edge);
    callers.set(edge.callee, calleeList);
  }

  return { nodes, edges, callers, callees };
}

/**
 * Find all callers of a function (who calls this?).
 */
export function findCallers(graph: CallGraph, functionKey: string): CallEdge[] {
  return graph.callers.get(functionKey) || [];
}

/**
 * Find all callees of a function (what does this call?).
 */
export function findCallees(graph: CallGraph, functionKey: string): CallEdge[] {
  return graph.callees.get(functionKey) || [];
}

/**
 * Trace the call chain from entry point to a target function.
 * Returns all paths as arrays of function keys.
 */
export function traceCallPaths(
  graph: CallGraph,
  from: string,
  to: string,
  maxDepth = 10
): string[][] {
  const paths: string[][] = [];

  function dfs(current: string, path: string[], visited: Set<string>) {
    if (path.length > maxDepth) return;
    if (current === to) {
      paths.push([...path, current]);
      return;
    }
    if (visited.has(current)) return;
    visited.add(current);

    const calls = graph.callees.get(current) || [];
    for (const edge of calls) {
      dfs(edge.callee, [...path, current], new Set(visited));
    }
  }

  dfs(from, [], new Set());
  return paths;
}

function resolveCall(
  name: string,
  fromFile: string,
  funcByName: Map<string, FunctionDef[]>,
  importMap: Map<string, Map<string, string>>
): string | null {
  // Check imports first
  const fileImports = importMap.get(fromFile);
  if (fileImports?.has(name)) {
    const source = fileImports.get(name)!;
    // Find the function in the source module
    const candidates = funcByName.get(name) || [];
    for (const c of candidates) {
      if (c.file.includes(source.replace(/^\.\//, "").replace(/\.\w+$/, ""))) {
        return `${c.file}:${c.name}`;
      }
    }
    return `${source}:${name}`;
  }

  // Check same-file functions
  const candidates = funcByName.get(name) || [];
  const sameFile = candidates.find((c) => c.file === fromFile);
  if (sameFile) return `${sameFile.file}:${sameFile.name}`;

  // Check globally (ambiguous — return first match)
  if (candidates.length === 1) return `${candidates[0].file}:${candidates[0].name}`;

  return null;
}

function isKeyword(name: string): boolean {
  const keywords = new Set([
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "return",
    "throw",
    "try",
    "catch",
    "finally",
    "new",
    "typeof",
    "instanceof",
    "import",
    "export",
    "from",
    "require",
    "console",
    "process",
    "Promise",
    "Array",
    "Object",
    "String",
    "Number",
    "Boolean",
    "Map",
    "Set",
    "Error",
    "JSON",
    "Math",
    "Date",
    "RegExp",
    "parseInt",
    "parseFloat",
    "setTimeout",
    "setInterval",
    "print",
    "len",
    "range",
    "str",
    "int",
    "float",
    "list",
    "dict",
    "fmt",
    "log",
    "make",
    "append",
  ]);
  return keywords.has(name);
}
