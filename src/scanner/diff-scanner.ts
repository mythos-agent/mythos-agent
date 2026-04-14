import { execSync } from "node:child_process";
import path from "node:path";

export interface DiffFile {
  file: string;
  status: "added" | "modified" | "deleted";
}

export function getGitChangedFiles(
  projectPath: string,
  base?: string
): DiffFile[] {
  const cwd = path.resolve(projectPath);

  try {
    // Check if it's a git repo
    execSync("git rev-parse --git-dir", { cwd, stdio: "pipe" });
  } catch {
    return [];
  }

  const files: DiffFile[] = [];

  if (base) {
    // Changes vs a branch/commit
    const output = execSync(`git diff --name-status ${base}`, {
      cwd,
      encoding: "utf-8",
    });
    files.push(...parseDiffOutput(output));
  } else {
    // Staged changes
    const staged = execSync("git diff --name-status --cached", {
      cwd,
      encoding: "utf-8",
    });
    files.push(...parseDiffOutput(staged));

    // Unstaged changes
    const unstaged = execSync("git diff --name-status", {
      cwd,
      encoding: "utf-8",
    });
    files.push(...parseDiffOutput(unstaged));

    // Untracked files
    const untracked = execSync("git ls-files --others --exclude-standard", {
      cwd,
      encoding: "utf-8",
    });
    for (const line of untracked.trim().split("\n")) {
      if (line.trim()) {
        files.push({ file: line.trim(), status: "added" });
      }
    }
  }

  // Deduplicate
  const seen = new Set<string>();
  return files.filter((f) => {
    if (seen.has(f.file)) return false;
    seen.add(f.file);
    return f.status !== "deleted";
  });
}

function parseDiffOutput(output: string): DiffFile[] {
  return output
    .trim()
    .split("\n")
    .filter((l) => l.trim())
    .map((line) => {
      const [status, ...rest] = line.split("\t");
      const file = rest.join("\t");
      return {
        file,
        status: status.startsWith("A")
          ? ("added" as const)
          : status.startsWith("D")
            ? ("deleted" as const)
            : ("modified" as const),
      };
    });
}
