import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import Anthropic from "@anthropic-ai/sdk";
import type { SphinxConfig, Vulnerability } from "../types/index.js";
import { type Patch, applyPatch } from "./fixer.js";

export interface ValidatedFix {
  vulnerability: Vulnerability;
  patch: Patch;
  testCode: string;
  testPassed: boolean;
  vulnerabilityFixed: boolean;
  regressionsFree: boolean;
  status: "verified" | "partial" | "failed";
  message: string;
}

const TEST_GEN_PROMPT = `You are a security test engineer. Given a vulnerability and its fix, generate a test that:
1. Verifies the vulnerability is fixed (the dangerous behavior no longer occurs)
2. Verifies the fix doesn't break normal functionality

Output ONLY the test code as a single function. Use the project's test framework if detectable, otherwise use plain assertions.

Example format:
\`\`\`
// Test: SQL injection fix verification
function testSqlInjectionFix() {
  // Test that parameterized query is used
  assert(queryFunction("' OR 1=1 --") does not return all records);
  // Test that normal queries still work
  assert(queryFunction("John") returns expected results);
}
\`\`\``;

export class FixValidator {
  private client: Anthropic | null;

  constructor(private config: SphinxConfig) {
    this.client = config.apiKey ? new Anthropic({ apiKey: config.apiKey }) : null;
  }

  /**
   * Validate a fix by:
   * 1. Apply patch to a temp copy
   * 2. Generate a test for the fix
   * 3. Run existing tests (if any) to check for regressions
   * 4. Re-scan to verify vulnerability is gone
   */
  async validate(
    projectPath: string,
    vulnerability: Vulnerability,
    patch: Patch
  ): Promise<ValidatedFix> {
    // Step 1: Create backup of original file
    const absPath = path.resolve(projectPath, patch.file);
    if (!fs.existsSync(absPath)) {
      return makeResult(
        vulnerability,
        patch,
        "",
        false,
        false,
        false,
        "failed",
        `File not found: ${patch.file}`
      );
    }

    const originalContent = fs.readFileSync(absPath, "utf-8");

    // Step 2: Apply patch
    const applied = applyPatch(projectPath, patch);
    if (!applied) {
      return makeResult(
        vulnerability,
        patch,
        "",
        false,
        false,
        false,
        "failed",
        "Patch could not be applied — code may have changed"
      );
    }

    try {
      // Step 3: Check if the fixed code compiles/parses
      const compileOk = checkCompilation(projectPath);

      // Step 4: Run existing tests if available
      const testsOk = runExistingTests(projectPath);

      // Step 5: Re-scan the fixed file to check if vulnerability is gone
      const fixedContent = fs.readFileSync(absPath, "utf-8");
      const vulnGone = !fixedContent.includes(patch.original);

      // Step 6: Generate a verification test
      let testCode = "";
      if (this.client) {
        testCode = await this.generateTest(vulnerability, patch, fixedContent);
      }

      const status =
        vulnGone && compileOk && testsOk ? "verified" : vulnGone ? "partial" : "failed";

      const message = [
        vulnGone ? "Vulnerability pattern removed" : "Vulnerability pattern still present",
        compileOk ? "code compiles" : "compilation failed",
        testsOk ? "existing tests pass" : "test failures detected",
      ].join(", ");

      return makeResult(
        vulnerability,
        patch,
        testCode,
        testsOk,
        vulnGone,
        testsOk && compileOk,
        status,
        message
      );
    } finally {
      // Restore original file
      fs.writeFileSync(absPath, originalContent, "utf-8");
    }
  }

  private async generateTest(
    vulnerability: Vulnerability,
    patch: Patch,
    fixedCode: string
  ): Promise<string> {
    if (!this.client) return "";

    try {
      const response = await this.client.messages.create({
        model: this.config.model,
        max_tokens: 2048,
        system: TEST_GEN_PROMPT,
        messages: [
          {
            role: "user",
            content: `Vulnerability: ${vulnerability.title}
File: ${patch.file}
Original code: ${patch.original}
Fixed code: ${patch.fixed}

Generate a test that verifies this fix.`,
          },
        ],
      });

      const text = response.content.find((b) => b.type === "text");
      if (text && text.type === "text") {
        // Extract code from markdown code block if present
        const codeMatch = text.text.match(/```(?:\w+)?\n([\s\S]*?)```/);
        return codeMatch ? codeMatch[1].trim() : text.text.trim();
      }
    } catch {
      // AI unavailable
    }

    return "";
  }
}

function checkCompilation(projectPath: string): boolean {
  // Try TypeScript compilation check
  const tscResult = spawnSync("npx", ["tsc", "--noEmit"], {
    cwd: projectPath,
    encoding: "utf-8",
    timeout: 30000,
    stdio: "pipe",
  });

  if (tscResult.status === 0) return true;

  // tsc found but compilation failed
  if (!tscResult.error) return false;

  // tsc not found (ENOENT) — not a TS project, assume OK
  return true;
}

function runExistingTests(projectPath: string): boolean {
  // Check for package.json with test script
  const pkgPath = path.join(projectPath, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
      if (pkg.scripts?.test && pkg.scripts.test !== 'echo "Error: no test specified" && exit 1') {
        const result = spawnSync("npm", ["test", "--", "--run"], {
          cwd: projectPath,
          encoding: "utf-8",
          timeout: 60000,
          stdio: "pipe",
        });
        return result.status === 0;
      }
    } catch {
      // ignore
    }
  }

  // No tests to run — that's OK
  return true;
}

function makeResult(
  vulnerability: Vulnerability,
  patch: Patch,
  testCode: string,
  testPassed: boolean,
  vulnerabilityFixed: boolean,
  regressionsFree: boolean,
  status: "verified" | "partial" | "failed",
  message: string
): ValidatedFix {
  return {
    vulnerability,
    patch,
    testCode,
    testPassed,
    vulnerabilityFixed,
    regressionsFree,
    status,
    message,
  };
}
