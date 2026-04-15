import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface RaceRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}

const RACE_RULES: RaceRule[] = [
  // TOCTOU (Time of Check to Time of Use)
  {
    id: "race-toctou-fs",
    title: "Race Condition: TOCTOU in File Operations",
    description: "File existence checked before use. Between check and use, the file could be modified or removed by another process.",
    severity: "medium",
    cwe: "CWE-367",
    patterns: [
      /(?:existsSync|access|stat)\s*\(.*\)[\s\S]{0,50}(?:readFile|writeFile|unlink|rename|open)/gi,
      /os\.path\.exists\s*\(.*\)[\s\S]{0,50}open\s*\(/gi,
    ],
  },

  // Non-atomic read-modify-write
  {
    id: "race-read-modify-write",
    title: "Race Condition: Non-Atomic Read-Modify-Write",
    description: "Value read from database/storage, modified, then written back without locking. Concurrent requests can overwrite each other's changes.",
    severity: "high",
    cwe: "CWE-362",
    patterns: [
      /(?:find|get|read|fetch|load)\w*\s*\([\s\S]{0,100}(?:save|update|write|set|put)\w*\s*\(/gi,
      /balance\s*=.*balance\s*[-+]/gi,
      /count\s*=.*count\s*[+\-]/gi,
      /\.increment\s*\((?!.*(?:lock|transaction|atomic))/gi,
    ],
  },

  // Missing database transaction
  {
    id: "race-no-transaction",
    title: "Race Condition: Multiple DB Operations Without Transaction",
    description: "Multiple database operations that should be atomic are not wrapped in a transaction. Partial failures leave data inconsistent.",
    severity: "high",
    cwe: "CWE-362",
    patterns: [
      /await\s+\w+\.(?:create|update|delete|destroy|save)\s*\([^)]*\)\s*;\s*\n\s*await\s+\w+\.(?:create|update|delete|destroy|save)(?![\s\S]{0,500}transaction)/gi,
    ],
  },

  // Shared mutable state without lock
  {
    id: "race-shared-state",
    title: "Race Condition: Shared Mutable State Without Synchronization",
    description: "Global/shared variable modified in async handler without lock or atomic operation. Concurrent requests cause data corruption.",
    severity: "medium",
    cwe: "CWE-362",
    patterns: [
      /(?:let|var)\s+\w+\s*=\s*(?:0|\[\]|\{\})[\s\S]{0,200}(?:app|router)\.(?:get|post|put|delete)/gi,
    ],
  },

  // Double-spend / duplicate processing
  {
    id: "race-double-spend",
    title: "Race Condition: No Idempotency Check",
    description: "Payment or state-changing operation without idempotency key or duplicate check. Concurrent requests can process the same operation twice.",
    severity: "high",
    cwe: "CWE-362",
    patterns: [
      /(?:payment|charge|transfer|withdraw|debit)\s*(?:async)?\s*(?:function|\()(?![\s\S]{0,300}(?:idempotency|deduplicate|nonce|requestId))/gi,
    ],
  },

  // Async without await (fire and forget)
  {
    id: "race-fire-forget",
    title: "Race Condition: Async Operation Without Await",
    description: "Async database or API call without await. The response is sent before the operation completes, causing inconsistent state.",
    severity: "medium",
    cwe: "CWE-362",
    patterns: [
      /(?!await\s)(?:model|db|collection|repository)\.\w+\s*\([^)]*\)\s*;\s*\n\s*res\.(?:json|send|status)/gi,
    ],
  },

  // Go-specific: goroutine data race
  {
    id: "race-go-goroutine",
    title: "Race Condition: Goroutine Accessing Shared Variable",
    description: "Variable accessed inside a goroutine without mutex or channel. Use sync.Mutex or pass by value.",
    severity: "high",
    cwe: "CWE-362",
    patterns: [
      /go\s+func\s*\(.*\)\s*\{[\s\S]{0,200}(?!.*(?:mu\.|Lock|Mutex|sync\.|chan\s))/gi,
    ],
  },
];

export interface RaceConditionScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class RaceConditionScanner {
  async scan(projectPath: string): Promise<RaceConditionScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java"],
      {
        cwd: projectPath,
        absolute: true,
        ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
        nodir: true,
      }
    );

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch { continue; }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of RACE_RULES) {
        for (const pattern of rule.patterns) {
          // Some race condition patterns need multi-line matching
          pattern.lastIndex = 0;
          const match = pattern.exec(content);
          if (match) {
            const lineNum = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `RACE-${String(idCounter++).padStart(4, "0")}`,
              rule: `race:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "race-condition",
              cwe: rule.cwe,
              confidence: "medium",
              location: {
                file: relativePath,
                line: lineNum,
                snippet: lines[lineNum - 1]?.trim() || "",
              },
            });
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
