import fs from "node:fs";
import path from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import type { SphinxConfig, Vulnerability } from "../types/index.js";

export interface Patch {
  vulnerabilityId: string;
  file: string;
  description: string;
  original: string;
  fixed: string;
  startLine: number;
  endLine: number;
}

const FIX_SYSTEM_PROMPT = `You are sphinx-agent, an expert security engineer. Your task is to generate precise, minimal patches that fix security vulnerabilities without breaking functionality.

## Rules

1. **Minimal changes only** — fix the vulnerability, don't refactor surrounding code
2. **Preserve behavior** — the fix must not break existing functionality
3. **Use best practices** — parameterized queries, proper escaping, safe APIs
4. **Include context** — enough surrounding lines so the patch can be applied unambiguously

## Output Format

Respond with a JSON array of patches:
[
  {
    "vulnerabilityId": "SPX-0001",
    "file": "src/api/users.ts",
    "description": "Use parameterized query instead of string concatenation",
    "startLine": 8,
    "endLine": 12,
    "original": "the original vulnerable code (exact lines from file)",
    "fixed": "the fixed code (replacement lines)"
  }
]

If a vulnerability cannot be safely auto-fixed (e.g., requires architectural changes), return a patch with fixed set to null and a description explaining why.`;

export class AIFixer {
  private client: Anthropic;
  private model: string;

  constructor(private config: SphinxConfig) {
    this.client = new Anthropic({ apiKey: config.apiKey });
    this.model = config.model;
  }

  async generatePatches(vulnerabilities: Vulnerability[], projectPath: string): Promise<Patch[]> {
    // Group vulnerabilities by file to minimize API calls
    const byFile = new Map<string, Vulnerability[]>();
    for (const v of vulnerabilities) {
      const file = v.location.file;
      const list = byFile.get(file) || [];
      list.push(v);
      byFile.set(file, list);
    }

    const allPatches: Patch[] = [];

    for (const [file, vulns] of byFile) {
      const absPath = path.resolve(projectPath, file);
      if (!fs.existsSync(absPath)) continue;

      const content = fs.readFileSync(absPath, "utf-8");
      const lines = content.split("\n");

      // Build context: show the vulnerable lines with surrounding context
      const vulnContexts = vulns.map((v) => {
        const start = Math.max(0, v.location.line - 6);
        const end = Math.min(lines.length, v.location.line + 5);
        const snippet = lines
          .slice(start, end)
          .map((line, i) => `${start + i + 1}\t${line}`)
          .join("\n");

        return `### ${v.id} [${v.severity.toUpperCase()}] — ${v.title}
Line ${v.location.line}: ${v.location.snippet || ""}
CWE: ${v.cwe || "N/A"}
Description: ${v.description}

Code context (${file}, lines ${start + 1}-${end}):
\`\`\`
${snippet}
\`\`\``;
      });

      const prompt = `Fix the following ${vulns.length} vulnerabilit${vulns.length > 1 ? "ies" : "y"} in \`${file}\`:

${vulnContexts.join("\n\n")}

Generate patches for each vulnerability. The "original" field must contain the EXACT text from the file that will be replaced, and "fixed" must contain the replacement text.`;

      try {
        const response = await this.client.messages.create({
          model: this.model,
          max_tokens: 4096,
          system: FIX_SYSTEM_PROMPT,
          messages: [{ role: "user", content: prompt }],
        });

        const textBlock = response.content.find((b) => b.type === "text");
        if (textBlock && textBlock.type === "text") {
          const patches = this.parsePatches(textBlock.text);
          allPatches.push(...patches);
        }
      } catch {
        // Skip this file on error, continue with others
      }
    }

    return allPatches;
  }

  private parsePatches(text: string): Patch[] {
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return [];

    try {
      const raw = JSON.parse(jsonMatch[0]) as Array<{
        vulnerabilityId: string;
        file: string;
        description: string;
        startLine: number;
        endLine: number;
        original: string;
        fixed: string | null;
      }>;

      return raw
        .filter((p) => p.fixed !== null)
        .map((p) => ({
          vulnerabilityId: p.vulnerabilityId,
          file: p.file,
          description: p.description,
          original: p.original,
          fixed: p.fixed!,
          startLine: p.startLine,
          endLine: p.endLine,
        }));
    } catch {
      return [];
    }
  }
}

export function applyPatch(projectPath: string, patch: Patch): boolean {
  const absPath = path.resolve(projectPath, patch.file);
  // Prevent path traversal — patch must stay within project
  if (!absPath.startsWith(path.resolve(projectPath) + path.sep)) return false;
  if (!fs.existsSync(absPath)) return false;

  let content = fs.readFileSync(absPath, "utf-8");

  if (!content.includes(patch.original)) {
    // Try trimmed match as fallback
    const trimmedOriginal = patch.original.trim();
    const lines = content.split("\n");
    let found = false;

    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim() === trimmedOriginal.split("\n")[0].trim()) {
        // Found the start line, try matching the rest
        const originalLines = trimmedOriginal.split("\n");
        let match = true;
        for (let j = 0; j < originalLines.length && i + j < lines.length; j++) {
          if (lines[i + j].trim() !== originalLines[j].trim()) {
            match = false;
            break;
          }
        }
        if (match) {
          const before = lines.slice(0, i);
          const after = lines.slice(i + originalLines.length);
          content = [...before, patch.fixed, ...after].join("\n");
          found = true;
          break;
        }
      }
    }

    if (!found) return false;
  } else {
    // Replace only the FIRST occurrence to avoid modifying unrelated code
    const idx = content.indexOf(patch.original);
    content = content.slice(0, idx) + patch.fixed + content.slice(idx + patch.original.length);
  }

  fs.writeFileSync(absPath, content, "utf-8");
  return true;
}
