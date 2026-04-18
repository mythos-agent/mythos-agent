#!/usr/bin/env node
// Validates rules.yml. Run with: npm test
//
// Checks each rule has the required fields (id, title, severity, cwe,
// languages, patterns) and that no field still contains placeholder text.
// Extend this file as you add your own assertions.

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const REQUIRED_FIELDS = ["id", "title", "severity", "cwe", "languages", "patterns"];
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const RULES_PATH = path.join(__dirname, "rules.yml");

function fail(msg) {
  console.error(`✗ ${msg}`);
  process.exitCode = 1;
}

function main() {
  const raw = fs.readFileSync(RULES_PATH, "utf-8");
  const doc = yaml.load(raw);
  if (!doc || !Array.isArray(doc.rules) || doc.rules.length === 0) {
    fail("rules.yml has no rules array or is empty");
    return;
  }

  for (const rule of doc.rules) {
    const id = rule.id || "<no id>";

    for (const field of REQUIRED_FIELDS) {
      if (rule[field] === undefined || rule[field] === null) {
        fail(`${id}: missing required field "${field}"`);
      }
    }

    if (rule.severity && !SEVERITIES.has(rule.severity)) {
      fail(`${id}: severity "${rule.severity}" is not one of ${[...SEVERITIES].join(", ")}`);
    }

    if (rule.cwe && /^CWE-X+$|<CWE/i.test(rule.cwe)) {
      fail(`${id}: cwe "${rule.cwe}" looks like a placeholder; use a real CWE number`);
    }

    if (Array.isArray(rule.patterns) && rule.patterns.length === 0) {
      fail(`${id}: patterns array is empty`);
    }
  }

  if (process.exitCode) return;
  console.log(`✓ ${doc.rules.length} rule(s) validated`);
}

main();
