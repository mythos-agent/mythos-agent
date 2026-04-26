import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type Anthropic from "@anthropic-ai/sdk";
import { findAstPattern, inferLanguage } from "../analysis/ast-matcher/index.js";

export function createAgentTools(projectPath: string): Anthropic.Tool[] {
  return [
    {
      name: "read_file",
      description:
        "Read the contents of a file in the project. Returns the file content with line numbers.",
      input_schema: {
        type: "object" as const,
        properties: {
          file_path: {
            type: "string",
            description: "Relative path to the file from the project root",
          },
          start_line: {
            type: "number",
            description: "Start reading from this line (1-based, default: 1)",
          },
          end_line: {
            type: "number",
            description: "Stop reading at this line (default: end of file, max 200 lines)",
          },
        },
        required: ["file_path"],
      },
    },
    {
      name: "search_code",
      description:
        "Search for a pattern across all files in the project. Returns matching lines with file paths and line numbers.",
      input_schema: {
        type: "object" as const,
        properties: {
          pattern: {
            type: "string",
            description: "Regex pattern to search for",
          },
          file_glob: {
            type: "string",
            description: 'File glob to limit search scope (e.g., "**/*.ts")',
          },
        },
        required: ["pattern"],
      },
    },
    {
      name: "list_files",
      description: "List files in a directory of the project.",
      input_schema: {
        type: "object" as const,
        properties: {
          directory: {
            type: "string",
            description: "Relative directory path (default: project root)",
          },
          glob_pattern: {
            type: "string",
            description: 'Glob pattern to filter files (e.g., "**/*.ts")',
          },
        },
        required: [],
      },
    },
    {
      name: "find_ast_pattern",
      description:
        "Find code matching a tree-sitter AST node kind across the project, " +
        "optionally filtered by regex predicates against each match's text. " +
        'Use this for variant-analysis-style searches where the "shape" of the ' +
        "code matters (e.g. `new RegExp(...)` calls, `function_declaration` " +
        "nodes accepting a specific parameter name) — not just the surface " +
        "text. JS/TS only at present. Pass `kind` as a single string or an " +
        "array of strings (union match).",
      input_schema: {
        type: "object" as const,
        properties: {
          kind: {
            type: ["string", "array"],
            items: { type: "string" },
            description:
              'tree-sitter node kind to match (e.g. "call_expression", "new_expression", "function_declaration", "regex", "template_string"). May be a single string or an array of strings for union matching.',
          },
          text_predicates: {
            type: "array",
            items: { type: "string" },
            description:
              "Optional list of regex strings; a node matches only if ALL predicates' regexes match its source text. Use to narrow `kind` matches to a specific shape (e.g. callee identifier, parameter name).",
          },
          file_glob: {
            type: "string",
            description:
              'File glob to limit scope. Defaults to all JS/TS files: "**/*.{ts,tsx,js,jsx,cts,cjs,mts,mjs}".',
          },
          max_matches: {
            type: "number",
            description: "Maximum number of matches to return (default: 50).",
          },
        },
        required: ["kind"],
      },
    },
  ];
}

export async function executeToolCall(
  projectPath: string,
  toolName: string,
  toolInput: Record<string, unknown>
): Promise<string> {
  switch (toolName) {
    case "read_file":
      return executeReadFile(projectPath, toolInput);
    case "search_code":
      return executeSearchCode(projectPath, toolInput);
    case "list_files":
      return executeListFiles(projectPath, toolInput);
    case "find_ast_pattern":
      return executeFindAstPattern(projectPath, toolInput);
    default:
      return `Unknown tool: ${toolName}`;
  }
}

function executeReadFile(projectPath: string, input: Record<string, unknown>): string {
  const filePath = input.file_path as string;
  const absPath = path.resolve(projectPath, filePath);

  // Security: prevent path traversal
  if (!absPath.startsWith(path.resolve(projectPath))) {
    return "Error: Access denied — path is outside project directory";
  }

  if (!fs.existsSync(absPath)) {
    return `Error: File not found: ${filePath}`;
  }

  const content = fs.readFileSync(absPath, "utf-8");
  const lines = content.split("\n");
  const start = Math.max(1, (input.start_line as number) || 1);
  const end = Math.min(
    lines.length,
    (input.end_line as number) || Math.min(lines.length, start + 199)
  );

  const numbered = lines
    .slice(start - 1, end)
    .map((line, i) => `${start + i}\t${line}`)
    .join("\n");

  return `File: ${filePath} (lines ${start}-${end} of ${lines.length})\n\n${numbered}`;
}

function executeSearchCode(projectPath: string, input: Record<string, unknown>): string {
  const pattern = input.pattern as string;
  const fileGlob = (input.file_glob as string) || "**/*.{ts,tsx,js,jsx,py}";

  let regex: RegExp;
  try {
    regex = new RegExp(pattern, "gi");
  } catch (err) {
    return `Error: Invalid regex pattern "${pattern}" — ${err instanceof Error ? err.message : "unknown error"}`;
  }

  const files = glob.sync(fileGlob, {
    cwd: projectPath,
    absolute: true,
    ignore: ["node_modules/**", "dist/**", ".git/**"],
    nodir: true,
  });

  const results: string[] = [];
  let matchCount = 0;
  const maxMatches = 50;

  for (const file of files) {
    if (matchCount >= maxMatches) break;
    const content = fs.readFileSync(file, "utf-8");
    const lines = content.split("\n");
    const relPath = path.relative(projectPath, file);

    for (let i = 0; i < lines.length; i++) {
      regex.lastIndex = 0;
      if (regex.test(lines[i])) {
        results.push(`${relPath}:${i + 1}\t${lines[i].trim()}`);
        matchCount++;
        if (matchCount >= maxMatches) break;
      }
    }
  }

  if (results.length === 0) {
    return `No matches found for pattern: ${pattern}`;
  }

  return `Found ${results.length} matches:\n\n${results.join("\n")}`;
}

function executeListFiles(projectPath: string, input: Record<string, unknown>): string {
  const dir = (input.directory as string) || ".";
  const globPattern = (input.glob_pattern as string) || "*";
  const absDir = path.resolve(projectPath, dir);

  if (!absDir.startsWith(path.resolve(projectPath))) {
    return "Error: Access denied — path is outside project directory";
  }

  const files = glob.sync(globPattern, {
    cwd: absDir,
    ignore: ["node_modules/**", "dist/**", ".git/**"],
  });

  return files.slice(0, 100).join("\n") || "No files found";
}

/**
 * `find_ast_pattern` tool dispatch — sub-PR A2 of variants v2 (see
 * docs/path-forward.md Track A and src/analysis/ast-matcher/).
 *
 * For each JS/TS file in the project, parse it with tree-sitter and
 * collect every node whose `type` matches `kind` (single or union)
 * AND whose source text passes every regex in `text_predicates`. This
 * is the structural counterpart to `search_code`: where `search_code`
 * finds lines matching a regex, `find_ast_pattern` finds nodes
 * matching a shape — which is what variant analysis actually needs.
 *
 * Why per-file matchers (not a single combined parse): tree-sitter
 * grammars are language-specific. A project with mixed JS and TS
 * needs both grammars; iterating files lets us pick the right one
 * per file via `inferLanguage`. Files in unsupported extensions are
 * skipped silently — that's better than emitting noise for every
 * `.md` / `.json` / `.css` in the tree.
 *
 * Result shape: a "filename:line\tkind:text" block, formatted to
 * resemble `search_code`'s output so downstream prompts can treat
 * the two tools' results uniformly.
 */
const FIND_AST_DEFAULT_GLOB = "**/*.{ts,tsx,js,jsx,cts,cjs,mts,mjs}";
const FIND_AST_DEFAULT_MAX = 50;
const FIND_AST_FILE_SIZE_CAP = 1_000_000; // 1 MB

async function executeFindAstPattern(
  projectPath: string,
  input: Record<string, unknown>
): Promise<string> {
  const kindRaw = input.kind;
  if (typeof kindRaw !== "string" && !Array.isArray(kindRaw)) {
    return "Error: `kind` must be a string or an array of strings";
  }
  const kind: string | string[] = Array.isArray(kindRaw)
    ? kindRaw.filter((k): k is string => typeof k === "string")
    : kindRaw;
  if (Array.isArray(kind) && kind.length === 0) {
    return "Error: `kind` array must contain at least one string";
  }

  const textPredicatesRaw = input.text_predicates;
  let textPredicates: string[] | undefined;
  if (textPredicatesRaw !== undefined) {
    if (!Array.isArray(textPredicatesRaw)) {
      return "Error: `text_predicates` must be an array of regex strings";
    }
    textPredicates = textPredicatesRaw.filter((p): p is string => typeof p === "string");
    // Validate up front — better to surface a regex syntax error here
    // than to fail silently on the first matching node.
    for (const pred of textPredicates) {
      try {
        new RegExp(pred, "u");
      } catch (err) {
        return `Error: Invalid regex in text_predicates "${pred}" — ${err instanceof Error ? err.message : "unknown error"}`;
      }
    }
  }

  const fileGlob = (input.file_glob as string) || FIND_AST_DEFAULT_GLOB;
  const maxMatches = (input.max_matches as number) || FIND_AST_DEFAULT_MAX;

  const files = glob.sync(fileGlob, {
    cwd: projectPath,
    absolute: true,
    ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
    nodir: true,
  });

  const results: string[] = [];
  let total = 0;
  let truncated = false;

  for (const file of files) {
    if (total >= maxMatches) {
      truncated = true;
      break;
    }
    const language = inferLanguage(file);
    if (!language) continue;

    let source: string;
    try {
      // Single read avoids the stat/read TOCTOU CodeQL flags
      // (js/file-system-race) and the wasted decode pass when a huge
      // file would have been skipped anyway. Buffer length is a
      // strict upper bound on UTF-8 character count.
      const buf = fs.readFileSync(file);
      if (buf.length > FIND_AST_FILE_SIZE_CAP) continue;
      source = buf.toString("utf-8");
    } catch {
      continue;
    }

    let matches;
    try {
      matches = await findAstPattern({
        kind,
        source,
        language,
        textPredicates,
        maxMatches: maxMatches - total,
      });
    } catch (err) {
      // Parser load failures (missing wasm, corrupted grammar) are
      // surfaced once at the file level rather than aborting the
      // whole search — the agent can still get partial results.
      results.push(
        `${path.relative(projectPath, file)}:0\tparse error: ${
          err instanceof Error ? err.message : "unknown"
        }`
      );
      continue;
    }

    const relPath = path.relative(projectPath, file);
    for (const m of matches) {
      const snippet = m.text.split("\n")[0].slice(0, 200);
      results.push(`${relPath}:${m.startLine}\t${m.kind}: ${snippet}`);
      total++;
      if (total >= maxMatches) {
        truncated = true;
        break;
      }
    }
  }

  if (results.length === 0) {
    const kindStr = Array.isArray(kind) ? kind.join("|") : kind;
    return `No AST matches found for kind: ${kindStr}`;
  }

  const header = `Found ${results.length} AST match${results.length === 1 ? "" : "es"}${
    truncated ? ` (truncated at max_matches=${maxMatches})` : ""
  }:`;
  return `${header}\n\n${results.join("\n")}`;
}
