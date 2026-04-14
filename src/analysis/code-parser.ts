import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";

export interface FunctionDef {
  name: string;
  file: string;
  line: number;
  endLine: number;
  params: string[];
  exported: boolean;
  async: boolean;
  kind: "function" | "method" | "arrow" | "handler";
}

export interface ImportDef {
  source: string;
  specifiers: string[];
  file: string;
  line: number;
}

export interface ClassDef {
  name: string;
  file: string;
  line: number;
  methods: string[];
  extends?: string;
}

export interface RouteDef {
  method: string;
  path: string;
  handler: string;
  file: string;
  line: number;
  middleware: string[];
}

export interface CodebaseMap {
  functions: FunctionDef[];
  imports: ImportDef[];
  classes: ClassDef[];
  routes: RouteDef[];
  exports: Array<{ name: string; file: string; line: number }>;
}

const SUPPORTED_EXTENSIONS = [
  ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".java", ".php",
];

/**
 * Parse a codebase and extract structural information.
 * Uses regex-based parsing (fast, no native deps).
 */
export async function parseCodebase(
  projectPath: string,
  excludePatterns = ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"]
): Promise<CodebaseMap> {
  const files = await glob(
    SUPPORTED_EXTENSIONS.map((ext) => `**/*${ext}`),
    { cwd: projectPath, absolute: true, ignore: excludePatterns, nodir: true }
  );

  const map: CodebaseMap = {
    functions: [],
    imports: [],
    classes: [],
    routes: [],
    exports: [],
  };

  for (const file of files) {
    const content = fs.readFileSync(file, "utf-8");
    const relPath = path.relative(projectPath, file);
    const ext = path.extname(file);

    if ([".ts", ".tsx", ".js", ".jsx"].includes(ext)) {
      parseJsTs(content, relPath, map);
    } else if (ext === ".py") {
      parsePython(content, relPath, map);
    } else if (ext === ".go") {
      parseGo(content, relPath, map);
    }
  }

  return map;
}

function parseJsTs(content: string, file: string, map: CodebaseMap): void {
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Imports
    const importMatch = line.match(
      /import\s+(?:\{([^}]+)\}|(\w+))\s+from\s+['"]([^'"]+)['"]/
    );
    if (importMatch) {
      const specifiers = importMatch[1]
        ? importMatch[1].split(",").map((s) => s.trim().split(/\s+as\s+/)[0])
        : [importMatch[2]];
      map.imports.push({
        source: importMatch[3],
        specifiers: specifiers.filter(Boolean),
        file,
        line: i + 1,
      });
    }

    // Function declarations
    const funcMatch = line.match(
      /^(export\s+)?(async\s+)?function\s+(\w+)\s*\(([^)]*)\)/
    );
    if (funcMatch) {
      map.functions.push({
        name: funcMatch[3],
        file,
        line: i + 1,
        endLine: findBlockEnd(lines, i),
        params: parseParams(funcMatch[4]),
        exported: !!funcMatch[1],
        async: !!funcMatch[2],
        kind: "function",
      });
    }

    // Arrow functions assigned to const/let
    const arrowMatch = line.match(
      /^(export\s+)?(const|let)\s+(\w+)\s*=\s*(async\s+)?\(?([^)]*)\)?\s*=>/
    );
    if (arrowMatch) {
      map.functions.push({
        name: arrowMatch[3],
        file,
        line: i + 1,
        endLine: findBlockEnd(lines, i),
        params: parseParams(arrowMatch[5]),
        exported: !!arrowMatch[1],
        async: !!arrowMatch[4],
        kind: "arrow",
      });
    }

    // Class declarations
    const classMatch = line.match(
      /^(export\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?/
    );
    if (classMatch) {
      const methods: string[] = [];
      for (let j = i + 1; j < lines.length && j < i + 200; j++) {
        const methodMatch = lines[j].match(
          /^\s+(async\s+)?(\w+)\s*\(/
        );
        if (methodMatch && methodMatch[2] !== "constructor") {
          methods.push(methodMatch[2]);
        }
        if (lines[j].match(/^}/)) break;
      }
      map.classes.push({
        name: classMatch[2],
        file,
        line: i + 1,
        methods,
        extends: classMatch[3],
      });
    }

    // Express/Fastify/Hono routes
    const routeMatch = line.match(
      /(?:app|router|server)\.(get|post|put|patch|delete|all|use)\s*\(\s*['"]([^'"]*)['"]/
    );
    if (routeMatch) {
      const middleware: string[] = [];
      // Look for middleware in the same line
      const middlewareMatch = line.match(/,\s*(\w+)\s*,/g);
      if (middlewareMatch) {
        middleware.push(
          ...middlewareMatch.map((m) => m.replace(/[, ]/g, ""))
        );
      }
      map.routes.push({
        method: routeMatch[1].toUpperCase(),
        path: routeMatch[2],
        handler: "",
        file,
        line: i + 1,
        middleware,
      });
    }

    // Next.js API routes (export default/GET/POST)
    const nextRouteMatch = line.match(
      /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(/
    );
    if (nextRouteMatch) {
      map.routes.push({
        method: nextRouteMatch[1],
        path: file.replace(/\\/g, "/"),
        handler: nextRouteMatch[1],
        file,
        line: i + 1,
        middleware: [],
      });
    }

    // Exports
    const exportMatch = line.match(
      /^export\s+(?:default\s+)?(?:const|let|var|function|class|async function)\s+(\w+)/
    );
    if (exportMatch) {
      map.exports.push({ name: exportMatch[1], file, line: i + 1 });
    }
  }
}

function parsePython(content: string, file: string, map: CodebaseMap): void {
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Imports
    const importMatch = line.match(/^(?:from\s+(\S+)\s+)?import\s+(.+)/);
    if (importMatch) {
      map.imports.push({
        source: importMatch[1] || importMatch[2].split(",")[0].trim(),
        specifiers: importMatch[2].split(",").map((s) => s.trim().split(/\s+as\s+/)[0]),
        file,
        line: i + 1,
      });
    }

    // Function definitions
    const funcMatch = line.match(
      /^(async\s+)?def\s+(\w+)\s*\(([^)]*)\)/
    );
    if (funcMatch) {
      map.functions.push({
        name: funcMatch[2],
        file,
        line: i + 1,
        endLine: findPythonBlockEnd(lines, i),
        params: parseParams(funcMatch[3]),
        exported: !funcMatch[2].startsWith("_"),
        async: !!funcMatch[1],
        kind: "function",
      });
    }

    // Class definitions
    const classMatch = line.match(/^class\s+(\w+)(?:\((\w+)\))?/);
    if (classMatch) {
      const methods: string[] = [];
      for (let j = i + 1; j < lines.length && j < i + 200; j++) {
        const methodMatch = lines[j].match(/^\s+(?:async\s+)?def\s+(\w+)/);
        if (methodMatch) methods.push(methodMatch[1]);
        if (j > i + 1 && lines[j].match(/^\S/) && lines[j].trim()) break;
      }
      map.classes.push({
        name: classMatch[1],
        file,
        line: i + 1,
        methods,
        extends: classMatch[2],
      });
    }

    // Flask/FastAPI routes
    const pyRouteMatch = line.match(
      /@(?:app|router|api)\.(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]*)['"]/
    );
    if (pyRouteMatch) {
      map.routes.push({
        method: pyRouteMatch[1].toUpperCase(),
        path: pyRouteMatch[2],
        handler: "",
        file,
        line: i + 1,
        middleware: [],
      });
    }
  }
}

function parseGo(content: string, file: string, map: CodebaseMap): void {
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Imports
    const importMatch = line.match(/^\s*"([^"]+)"/);
    if (importMatch && i > 0 && content.slice(0, content.indexOf(line)).includes("import")) {
      map.imports.push({
        source: importMatch[1],
        specifiers: [path.basename(importMatch[1])],
        file,
        line: i + 1,
      });
    }

    // Function definitions
    const funcMatch = line.match(
      /^func\s+(?:\((\w+)\s+\*?(\w+)\)\s+)?(\w+)\s*\(([^)]*)\)/
    );
    if (funcMatch) {
      const name = funcMatch[3];
      map.functions.push({
        name,
        file,
        line: i + 1,
        endLine: findBlockEnd(lines, i),
        params: parseParams(funcMatch[4]),
        exported: name[0] === name[0].toUpperCase(),
        async: false,
        kind: funcMatch[1] ? "method" : "function",
      });
    }

    // Go HTTP routes
    const goRouteMatch = line.match(
      /(?:Handle|HandleFunc|Get|Post|Put|Delete|Patch)\s*\(\s*['"]([^'"]*)['"]/
    );
    if (goRouteMatch) {
      map.routes.push({
        method: line.includes("Get") ? "GET" : line.includes("Post") ? "POST" : "ALL",
        path: goRouteMatch[1],
        handler: "",
        file,
        line: i + 1,
        middleware: [],
      });
    }
  }
}

function findBlockEnd(lines: string[], startLine: number): number {
  let depth = 0;
  let started = false;
  for (let i = startLine; i < lines.length && i < startLine + 500; i++) {
    for (const ch of lines[i]) {
      if (ch === "{") { depth++; started = true; }
      if (ch === "}") depth--;
    }
    if (started && depth === 0) return i + 1;
  }
  return startLine + 1;
}

function findPythonBlockEnd(lines: string[], startLine: number): number {
  const indent = lines[startLine].match(/^(\s*)/)?.[1].length || 0;
  for (let i = startLine + 1; i < lines.length && i < startLine + 500; i++) {
    const lineIndent = lines[i].match(/^(\s*)/)?.[1].length || 0;
    if (lines[i].trim() && lineIndent <= indent) return i;
  }
  return lines.length;
}

function parseParams(raw: string): string[] {
  if (!raw || !raw.trim()) return [];
  return raw
    .split(",")
    .map((p) => p.trim().split(/[:\s=]/)[0].trim())
    .filter(Boolean);
}
