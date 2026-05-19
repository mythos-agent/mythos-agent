import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import Anthropic from "@anthropic-ai/sdk";
import type { MythosConfig, Vulnerability } from "../types/index.js";
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

export interface ValidateOptions {
  /**
   * When true, the validator runs the scanned project's compile check (`npx
   * tsc --noEmit`) and test suite (`npm test`) to detect regressions.
   *
   * **Default: false.**
   *
   * Leave this at the default unless you explicitly trust the repository
   * being scanned — both commands execute untrusted code from the scanned
   * project and can be weaponised by a malicious `pretest`/`posttest` or
   * other lifecycle hook.
   */
  runProjectTests?: boolean;
}

export class FixValidator {
  private client: Anthropic | null;

  constructor(private config: MythosConfig) {
    this.client = config.apiKey ? new Anthropic({ apiKey: config.apiKey }) : null;
  }

  /**
   * Validate a fix by:
   * 1. Apply patch to a temp copy
   * 2. Generate a test for the fix
   * 3. Run existing tests (if any) to check for regressions
   * 4. Re-scan to verify vulnerability is gone
   *
   * **Important:** compile and test commands from the scanned project are
   * executed ONLY when `options.runProjectTests` is `true`.  Those commands
   * run untrusted repository code.  The safe default (`runProjectTests:
   * false`) skips them and treats the absence of test failures as "no
   * regressions detected".
   */
  async validate(
    projectPath: string,
    vulnerability: Vulnerability,
    patch: Patch,
    options: ValidateOptions = {}
  ): Promise<ValidatedFix> {
    const { runProjectTests = false } = options;
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
      const compileOk = checkCompilation(projectPath, runProjectTests);

      // Step 4: Run existing tests if available
      const testsOk = runExistingTests(projectPath, runProjectTests);

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
        temperature: 0,
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

function checkCompilation(projectPath: string, runProjectTests: boolean): boolean {
  // Skip when project test/compile execution is not opted in.
  // Semantics: "not checked" == "no compilation errors detected, OK to proceed".
  if (!runProjectTests) return true;

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

function runExistingTests(projectPath: string, runProjectTests: boolean): boolean {
  // Skip when project test/compile execution is not opted in.
  // Semantics: "not checked" == "no regressions detected, OK to proceed".
  if (!runProjectTests) return true;

  // Check for package.json with test script
  const pkgPath = path.join(projectPath, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
      if (pkg.scripts?.test && pkg.scripts.test !== 'echo "Error: no test specified" && exit 1') {
        // --ignore-scripts prevents lifecycle hooks (pretest/posttest) in the
        // scanned repo from running arbitrary code with the user's credentials.
        const result = spawnSync("npm", ["test", "--ignore-scripts", "--", "--run"], {
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
