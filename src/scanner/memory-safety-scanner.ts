import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const MEM_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  lang: string[];
  patterns: RegExp[];
}> = [
  // C/C++
  {
    id: "mem-buffer-overflow",
    title: "Memory: Potential Buffer Overflow",
    description:
      "Unsafe string/memory function without bounds checking. Use strncpy, snprintf, or bounded alternatives.",
    severity: "critical",
    cwe: "CWE-120",
    lang: ["c", "cpp"],
    patterns: [/(?:strcpy|strcat|sprintf|gets)\s*\(/gi, /scanf\s*\(\s*["']%s/gi],
  },
  {
    id: "mem-format-string",
    title: "Memory: Format String Vulnerability",
    description:
      "User input passed as format string to printf-family functions. Enables memory read/write.",
    severity: "critical",
    cwe: "CWE-134",
    lang: ["c", "cpp"],
    patterns: [
      /(?:printf|fprintf|sprintf|snprintf)\s*\(\s*(?!["'])(?:buf|str|input|data|arg|user|msg)/gi,
    ],
  },
  {
    id: "mem-malloc-no-check",
    title: "Memory: malloc/calloc Without NULL Check",
    description:
      "Memory allocation without checking for NULL return. Dereferencing NULL causes undefined behavior.",
    severity: "medium",
    cwe: "CWE-252",
    lang: ["c", "cpp"],
    patterns: [/=\s*(?:malloc|calloc|realloc)\s*\([^)]+\)\s*;(?!\s*if\s*\()/gi],
  },
  {
    id: "mem-use-after-free",
    title: "Memory: Potential Use-After-Free",
    description:
      "Pointer used after free(). The memory may be reallocated, causing corruption or code execution.",
    severity: "critical",
    cwe: "CWE-416",
    lang: ["c", "cpp"],
    patterns: [/free\s*\(\s*(\w+)\s*\)\s*;[\s\S]{0,100}\1\s*[->=\[.]/gi],
  },
  {
    id: "mem-double-free",
    title: "Memory: Potential Double Free",
    description:
      "Same pointer may be freed twice. Double-free corrupts heap metadata and enables exploitation.",
    severity: "critical",
    cwe: "CWE-415",
    lang: ["c", "cpp"],
    patterns: [/free\s*\(\s*(\w+)\s*\)[\s\S]{0,200}free\s*\(\s*\1\s*\)/gi],
  },
  {
    id: "mem-integer-overflow",
    title: "Memory: Integer Overflow in Size Calculation",
    description:
      "Multiplication used for buffer size calculation without overflow check. Can wrap to small allocation.",
    severity: "high",
    cwe: "CWE-190",
    lang: ["c", "cpp"],
    patterns: [/(?:malloc|calloc|alloc)\s*\(\s*\w+\s*\*\s*\w+\s*\)/gi],
  },
  // Rust unsafe
  {
    id: "mem-rust-unsafe",
    title: "Memory: Rust unsafe Block",
    description:
      "Unsafe block bypasses Rust's memory safety guarantees. Review for pointer dereferences, FFI calls, and transmutes.",
    severity: "medium",
    cwe: "CWE-119",
    lang: ["rust"],
    patterns: [/unsafe\s*\{/gi],
  },
  {
    id: "mem-rust-raw-pointer",
    title: "Memory: Rust Raw Pointer Dereference",
    description:
      "Dereferencing raw pointer in unsafe block. Ensure pointer is valid, aligned, and points to initialized memory.",
    severity: "high",
    cwe: "CWE-119",
    lang: ["rust"],
    patterns: [/\*(?:mut|const)\s+\w+.*unsafe/gi, /unsafe\s*\{[\s\S]{0,200}\*\w+/gi],
  },
  {
    id: "mem-rust-transmute",
    title: "Memory: Rust std::mem::transmute",
    description:
      "transmute reinterprets bits without any checks. Can easily cause undefined behavior.",
    severity: "high",
    cwe: "CWE-704",
    lang: ["rust"],
    patterns: [/(?:mem::)?transmute\s*[:<(]/gi],
  },
];

const LANG_EXT: Record<string, string[]> = {
  c: [".c", ".h"],
  cpp: [".cpp", ".cc", ".cxx", ".hpp", ".hxx"],
  rust: [".rs"],
};

export interface MemorySafetyScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class MemorySafetyScanner {
  async scan(projectPath: string): Promise<MemorySafetyScanResult> {
    const allExts = Object.values(LANG_EXT).flat();
    const patterns = allExts.map((ext) => `**/*${ext}`);

    const files = await glob(patterns, {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "target/**", "build/**"],
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

      const ext = path.extname(file);
      const lang = Object.entries(LANG_EXT).find(([, exts]) => exts.includes(ext))?.[0];
      if (!lang) continue;

      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);

      for (const rule of MEM_RULES) {
        if (!rule.lang.includes(lang)) continue;
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `MEM-${String(id++).padStart(4, "0")}`,
              rule: `mem:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "memory-safety",
              cwe: rule.cwe,
              confidence: "medium",
              location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" },
            });
            break;
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
