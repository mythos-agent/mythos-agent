/**
 * ReDoS regression tests for scanner patterns.
 *
 * These tests guard against reintroduction of wide negative-lookaheads in
 * race-condition-scanner and jwt-scanner. Each test:
 *   1. Constructs an adversarial input that would cause catastrophic backtracking
 *      if wide negative-lookaheads were still in the regex.
 *   2. Asserts completion under a generous time bound (1500 ms).
 *   3. Asserts the scanner still fires on matching patterns (no silent suppression).
 *   4. Asserts the scanner stays silent when a mitigation keyword is present.
 */
import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RaceConditionScanner } from "../race-condition-scanner.js";
import { JwtScanner } from "../jwt-scanner.js";

function createFixture(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-redos-"));
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

// ---------------------------------------------------------------------------
// RaceConditionScanner — race-no-transaction
// ---------------------------------------------------------------------------
describe("RaceConditionScanner — race-no-transaction ReDoS guard", () => {
  it("completes in <1500 ms on adversarial input (no 'transaction' keyword)", async () => {
    // 50 KB of repeated await db.create() pairs — no 'transaction' keyword anywhere.
    // With the old (?![\s\S]{0,500}transaction) lookahead this would retry the
    // forward scan at every position, O(n^2) in input length.
    const line = "await db.create(x);\n";
    const adversarial = line.repeat(2500); // ~50 KB
    const dir = createFixture({ "db.ts": adversarial });

    const start = Date.now();
    const scanner = new RaceConditionScanner();
    await scanner.scan(dir);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1500);
    cleanup(dir);
  });

  it("still fires race-no-transaction when two awaits are present without a transaction", async () => {
    const dir = createFixture({
      "db.ts": [
        "async function transfer() {",
        "  await db.create({ from: 1 });",
        "  await db.update({ to: 2 });",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-no-transaction"))).toBe(true);
    cleanup(dir);
  });

  it("suppresses race-no-transaction when 'transaction' is present in the window", async () => {
    const dir = createFixture({
      "db.ts": [
        "async function transfer() {",
        "  await db.transaction(async (t) => {",
        "    await db.create({ from: 1 }, { transaction: t });",
        "    await db.update({ to: 2 }, { transaction: t });",
        "  });",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-no-transaction"))).toBe(false);
    cleanup(dir);
  });
});

// ---------------------------------------------------------------------------
// RaceConditionScanner — race-go-goroutine
// ---------------------------------------------------------------------------
describe("RaceConditionScanner — race-go-goroutine ReDoS guard", () => {
  it("completes in <1500 ms on adversarial input (no sync primitives)", async () => {
    // 50 KB of repeated go func() { body lines — no Lock/Mutex/sync/chan keywords.
    const lines: string[] = [];
    for (let i = 0; i < 1000; i++) {
      lines.push(`go func() { doWork(${i}) }()`);
    }
    const adversarial = lines.join("\n");
    const dir = createFixture({ "main.go": adversarial });

    const start = Date.now();
    const scanner = new RaceConditionScanner();
    await scanner.scan(dir);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1500);
    cleanup(dir);
  });

  it("still fires race-go-goroutine when no sync primitive is present", async () => {
    const dir = createFixture({
      "main.go": [
        "func main() {",
        "  counter := 0",
        "  go func() {",
        "    counter++",
        "  }()",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-go-goroutine"))).toBe(true);
    cleanup(dir);
  });

  it("suppresses race-go-goroutine when a sync primitive is present in the window", async () => {
    const dir = createFixture({
      "main.go": [
        "func main() {",
        "  var mu sync.Mutex",
        "  counter := 0",
        "  go func() {",
        "    mu.Lock()",
        "    counter++",
        "    mu.Unlock()",
        "  }()",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-go-goroutine"))).toBe(false);
    cleanup(dir);
  });
});

// ---------------------------------------------------------------------------
// RaceConditionScanner — race-double-spend
// ---------------------------------------------------------------------------
describe("RaceConditionScanner — race-double-spend ReDoS guard", () => {
  it("completes in <1500 ms on adversarial input (no idempotency keywords)", async () => {
    // 50 KB of repeated payment/charge trigger lines — no idempotency keyword anywhere.
    // With the old (?![\s\S]{0,300}...) lookahead this would retry the forward
    // scan at every position, O(n^2) in input length.
    const lines: string[] = [];
    for (let i = 0; i < 1250; i++) {
      lines.push(`async function payment(amount) { return charge(amount); }`);
      lines.push(`async function transfer(from, to) { return withdraw(from, amount); }`);
    }
    const adversarial = lines.join("\n"); // ~50 KB
    const dir = createFixture({ "payments.ts": adversarial });

    const start = Date.now();
    const scanner = new RaceConditionScanner();
    await scanner.scan(dir);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1500);
    cleanup(dir);
  });

  it("still fires race-double-spend when no idempotency check is present", async () => {
    const dir = createFixture({
      "payments.ts": [
        "async function payment(amount, userId) {",
        "  const result = await stripe.charge({ amount, currency: 'usd' });",
        "  await db.save(result);",
        "  return result;",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-double-spend"))).toBe(true);
    cleanup(dir);
  });

  it("suppresses race-double-spend when 'idempotency' is present in the window", async () => {
    const dir = createFixture({
      "payments.ts": [
        "async function payment(amount, idempotencyKey) {",
        "  const result = await stripe.charge({ amount, idempotency_key: idempotencyKey });",
        "  return result;",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-double-spend"))).toBe(false);
    cleanup(dir);
  });

  it("suppresses race-double-spend when 'deduplicate' is present in the window", async () => {
    const dir = createFixture({
      "payments.ts": [
        "async function transfer(from, to, amount) {",
        "  if (await deduplicate(requestId)) return;",
        "  await db.transfer(from, to, amount);",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-double-spend"))).toBe(false);
    cleanup(dir);
  });

  it("suppresses race-double-spend when 'nonce' is present in the window", async () => {
    const dir = createFixture({
      "payments.ts": [
        "async function withdraw(account, amount) {",
        "  const nonce = generateNonce();",
        "  await db.withdraw(account, amount, nonce);",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-double-spend"))).toBe(false);
    cleanup(dir);
  });

  it("suppresses race-double-spend when 'requestId' is present in the window", async () => {
    const dir = createFixture({
      "payments.ts": [
        "async function charge(userId, amount, requestId) {",
        "  await idempotentOp(requestId, async () => {",
        "    await billing.charge(userId, amount);",
        "  });",
        "}",
      ].join("\n"),
    });
    const { findings } = await new RaceConditionScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("race-double-spend"))).toBe(false);
    cleanup(dir);
  });
});

// ---------------------------------------------------------------------------
// JwtScanner — jwt-no-expiry
// ---------------------------------------------------------------------------
describe("JwtScanner — jwt-no-expiry ReDoS guard", () => {
  it("completes in <1500 ms on adversarial input (no expiresIn/exp)", async () => {
    // 50 KB of repeated jwt.sign({}) calls with no expiry keyword.
    const line = 'const t = jwt.sign({ sub: "user" }, secret);\n';
    const adversarial = line.repeat(1000); // ~50 KB
    const dir = createFixture({ "auth.ts": adversarial });

    const start = Date.now();
    const scanner = new JwtScanner();
    await scanner.scan(dir);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1500);
    cleanup(dir);
  });

  it("still fires jwt-no-expiry when no expiry option is present", async () => {
    const dir = createFixture({
      "auth.ts": 'const token = jwt.sign({ sub: "user" }, secret);',
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("jwt-no-expiry"))).toBe(true);
    cleanup(dir);
  });

  it("suppresses jwt-no-expiry when expiresIn is present in the window", async () => {
    const dir = createFixture({
      "auth.ts": [
        "const token = jwt.sign({",
        '  sub: "user",',
        "}, secret, { expiresIn: '1h' });",
      ].join("\n"),
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("jwt-no-expiry"))).toBe(false);
    cleanup(dir);
  });

  it("suppresses jwt-no-expiry when exp claim is present", async () => {
    const dir = createFixture({
      "auth.ts": [
        "const now = Math.floor(Date.now() / 1000);",
        "const token = jwt.sign({",
        '  sub: "user",',
        "  exp: now + 3600,",
        "}, secret);",
      ].join("\n"),
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("jwt-no-expiry"))).toBe(false);
    cleanup(dir);
  });
});

// ---------------------------------------------------------------------------
// JwtScanner — jwt-no-revocation
// ---------------------------------------------------------------------------
describe("JwtScanner — jwt-no-revocation ReDoS guard", () => {
  it("completes in <1500 ms on adversarial input (no revocation keyword)", async () => {
    // 50 KB of repeated jwt.verify() calls with no revocation keywords.
    const line = "const payload = jwt.verify(token, secret);\n";
    const adversarial = line.repeat(1000); // ~50 KB
    const dir = createFixture({ "auth.ts": adversarial });

    const start = Date.now();
    const scanner = new JwtScanner();
    await scanner.scan(dir);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1500);
    cleanup(dir);
  });

  it("still fires jwt-no-revocation when no revocation mechanism is present", async () => {
    const dir = createFixture({
      "auth.ts": [
        'import jwt from "jsonwebtoken";',
        "function verifyToken(token) {",
        "  return jwt.verify(token, secret);",
        "}",
      ].join("\n"),
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("jwt-no-revocation"))).toBe(true);
    cleanup(dir);
  });

  it("suppresses jwt-no-revocation when a blacklist check is present in the window", async () => {
    const dir = createFixture({
      "auth.ts": [
        'import jwt from "jsonwebtoken";',
        "async function verifyToken(token) {",
        "  const payload = jwt.verify(token, secret);",
        "  if (await blacklist.has(token)) throw new Error('revoked');",
        "  return payload;",
        "}",
      ].join("\n"),
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("jwt-no-revocation"))).toBe(false);
    cleanup(dir);
  });

  it("suppresses jwt-no-revocation when redis cache is present in the window", async () => {
    const dir = createFixture({
      "auth.ts": [
        'import jwt from "jsonwebtoken";',
        'import { redis } from "./cache";',
        "async function verifyToken(token) {",
        "  const payload = jwt.verify(token, secret);",
        "  const revoked = await redis.get(`revoked:${token}`);",
        "  if (revoked) throw new Error('token revoked');",
        "  return payload;",
        "}",
      ].join("\n"),
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("jwt-no-revocation"))).toBe(false);
    cleanup(dir);
  });
});
