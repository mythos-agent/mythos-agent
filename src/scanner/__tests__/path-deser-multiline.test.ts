/**
 * path-deser-multiline.test.ts
 *
 * Tests that path-scanner and deserialization-scanner correctly see
 * mitigations on the NEXT line (not just the same line) and do NOT
 * fire false positives when a guard is immediately below the match.
 *
 * These tests were written BEFORE the fix (TDD) and are expected to
 * FAIL until the scanners are updated to use mitigationCheck callbacks.
 */
import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PathScanner } from "../path-scanner.js";
import { DeserializationScanner } from "../deserialization-scanner.js";

const tmpDirs: string[] = [];

function fixture(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-multiline-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// path-traversal-resolve
// ---------------------------------------------------------------------------
describe("PathScanner — path-traversal-resolve", () => {
  it("fires when there is NO startsWith guard (true positive)", async () => {
    const dir = fixture({
      "server.ts": [
        "import path from 'path';",
        "const fullPath = path.resolve(userDir, req.query.file);",
        "fs.readFileSync(fullPath);",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-traversal-resolve"))).toBe(true);
  });

  it("does NOT fire when startsWith guard is on the next line (false-positive fix)", async () => {
    const dir = fixture({
      "server.ts": [
        "import path from 'path';",
        "const fullPath = path.resolve(userDir, req.query.file);",
        "if (!fullPath.startsWith(allowedDir)) {",
        "  return res.status(403).send('Forbidden');",
        "}",
        "fs.readFileSync(fullPath);",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-traversal-resolve"))).toBe(false);
  });

  it("does NOT fire when startsWith guard is on the same line (pre-existing behavior preserved)", async () => {
    const dir = fixture({
      "server.ts": [
        "import path from 'path';",
        "const fullPath = path.resolve(userDir, req.query.file); if (!fullPath.startsWith(allowedDir)) throw new Error();",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-traversal-resolve"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// path-dot-dot
// ---------------------------------------------------------------------------
describe("PathScanner — path-dot-dot", () => {
  it("fires when there is NO sanitization (true positive)", async () => {
    const dir = fixture({
      "files.ts": [
        "import fs from 'fs';",
        "fs.readFile(req.params.filepath, (err, data) => { res.send(data); });",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-dot-dot"))).toBe(true);
  });

  it("does NOT fire when startsWith guard is on the next line (false-positive fix)", async () => {
    const dir = fixture({
      "files.ts": [
        "import fs from 'fs';",
        "const resolved = path.resolve(base, req.params.filepath);",
        "fs.readFile(req.params.filepath, callback);",
        "if (!resolved.startsWith(allowedDir)) {",
        "  return res.status(403).end();",
        "}",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-dot-dot"))).toBe(false);
  });

  it("does NOT fire when normalize is used on the next line (false-positive fix)", async () => {
    const dir = fixture({
      "files.ts": [
        "import fs from 'fs';",
        "fs.readFile(input, callback);",
        "const safe = path.normalize(input);",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-dot-dot"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// path-null-byte
// ---------------------------------------------------------------------------
describe("PathScanner — path-null-byte", () => {
  it("fires when there is NO sanitization (true positive)", async () => {
    const dir = fixture({
      "open.ts": ["import fs from 'fs';", "fs.readFile(req.query.filename, 'utf-8', cb);"].join(
        "\n"
      ),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-null-byte"))).toBe(true);
  });

  it("does NOT fire when null-byte replacement is on the next line (false-positive fix)", async () => {
    const dir = fixture({
      "open.ts": [
        "import fs from 'fs';",
        "fs.readFile(req.query.filename, 'utf-8', cb);",
        "const safe = req.query.filename.replace(/\\0/g, '');",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-null-byte"))).toBe(false);
  });

  it("does NOT fire when sanitize is present within the window (false-positive fix)", async () => {
    const dir = fixture({
      "open.ts": [
        "import fs from 'fs';",
        "fs.access(req.query.file, fs.constants.F_OK, (err) => {",
        "  const safe = sanitize(req.query.file);",
        "  if (err) return res.status(404).end();",
        "});",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-null-byte"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// path-symlink
// ---------------------------------------------------------------------------
describe("PathScanner — path-symlink", () => {
  it("fires when there is NO lstat/realpath check (true positive)", async () => {
    const dir = fixture({
      "upload.ts": [
        "import fs from 'fs';",
        "fs.readFile(upload.path, (err, data) => { res.send(data); });",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-symlink"))).toBe(true);
  });

  it("does NOT fire when realpath is used on the next line (false-positive fix)", async () => {
    const dir = fixture({
      "upload.ts": [
        "import fs from 'fs';",
        "fs.readFile(upload.path, (err, data) => { res.send(data); });",
        "const real = fs.realpathSync(upload.path);",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-symlink"))).toBe(false);
  });

  it("does NOT fire when lstat is used within the window (false-positive fix)", async () => {
    const dir = fixture({
      "upload.ts": [
        "import fs from 'fs';",
        "fs.stat(user.avatarPath, (err, stat) => {",
        "  fs.lstat(user.avatarPath, (e, lst) => {",
        "    if (lst.isSymbolicLink()) throw new Error('symlink not allowed');",
        "  });",
        "});",
      ].join("\n"),
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("path-symlink"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// deser-json-parse-untrusted
// ---------------------------------------------------------------------------
describe("DeserializationScanner — deser-json-parse-untrusted", () => {
  it("fires when JSON.parse has no try/catch (true positive)", async () => {
    const dir = fixture({
      "handler.ts": [
        "function handle(msg) {",
        "  const data = JSON.parse(payload);",
        "  return data;",
        "}",
      ].join("\n"),
    });
    const { findings } = await new DeserializationScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("deser-json-parse-untrusted"))).toBe(true);
  });

  it("does NOT fire when try/catch wraps JSON.parse on the next lines (false-positive fix)", async () => {
    const dir = fixture({
      "handler.ts": [
        "function handle(msg) {",
        "  try {",
        "    const data = JSON.parse(payload);",
        "    return data;",
        "  } catch (e) {",
        "    return null;",
        "  }",
        "}",
      ].join("\n"),
    });
    const { findings } = await new DeserializationScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("deser-json-parse-untrusted"))).toBe(false);
  });

  it("still fires when no catch is in the window (a comment mentioning catch does not count)", async () => {
    const dir = fixture({
      "ws.ts": [
        "ws.on('message', (message) => {",
        "  const data = JSON.parse(message);",
        "  processData(data);",
        "  saveToDb(data);",
        "});",
        "// catch handled externally",
      ].join("\n"),
    });
    // The trailing comment is outside the 5-line window, so this remains a true positive.
    const { findings } = await new DeserializationScanner().scan(dir);
    expect(findings.some((f) => f.rule.includes("deser-json-parse-untrusted"))).toBe(true);
  });

  // The plan explicitly requires that deser-json-parse-untrusted emits
  // confidence "medium" (not "high") because even with a window check,
  // the rule has a known false-positive rate (catch block may exist
  // elsewhere in the function without being in the scan window).
  // This assertion documents and enforces that design decision.
  it("emits confidence 'medium' for deser-json-parse-untrusted (not high)", async () => {
    const dir = fixture({
      "handler.ts": [
        "function handle(msg) {",
        "  const data = JSON.parse(payload);",
        "  return data;",
        "}",
      ].join("\n"),
    });
    const { findings } = await new DeserializationScanner().scan(dir);
    const f = findings.find((f) => f.rule.includes("deser-json-parse-untrusted"));
    expect(f).toBeDefined();
    // Must be "medium" — "high" is incorrect given the single-line scan's
    // known false-positive rate when mitigations exist on adjacent lines.
    expect(f?.confidence).toBe("medium");
  });
});
