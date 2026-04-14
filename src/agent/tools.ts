import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type Anthropic from "@anthropic-ai/sdk";

export function createAgentTools(
  projectPath: string
): Anthropic.Tool[] {
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
            description:
              "Relative path to the file from the project root",
          },
          start_line: {
            type: "number",
            description: "Start reading from this line (1-based, default: 1)",
          },
          end_line: {
            type: "number",
            description:
              "Stop reading at this line (default: end of file, max 200 lines)",
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
            description:
              'File glob to limit search scope (e.g., "**/*.ts")',
          },
        },
        required: ["pattern"],
      },
    },
    {
      name: "list_files",
      description:
        "List files in a directory of the project.",
      input_schema: {
        type: "object" as const,
        properties: {
          directory: {
            type: "string",
            description:
              "Relative directory path (default: project root)",
          },
          glob_pattern: {
            type: "string",
            description: 'Glob pattern to filter files (e.g., "**/*.ts")',
          },
        },
        required: [],
      },
    },
  ];
}

export function executeToolCall(
  projectPath: string,
  toolName: string,
  toolInput: Record<string, unknown>
): string {
  switch (toolName) {
    case "read_file":
      return executeReadFile(projectPath, toolInput);
    case "search_code":
      return executeSearchCode(projectPath, toolInput);
    case "list_files":
      return executeListFiles(projectPath, toolInput);
    default:
      return `Unknown tool: ${toolName}`;
  }
}

function executeReadFile(
  projectPath: string,
  input: Record<string, unknown>
): string {
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

function executeSearchCode(
  projectPath: string,
  input: Record<string, unknown>
): string {
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

function executeListFiles(
  projectPath: string,
  input: Record<string, unknown>
): string {
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
