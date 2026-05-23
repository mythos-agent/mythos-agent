import fs from "node:fs";
const r = JSON.parse(fs.readFileSync(process.argv[2], "utf-8"));
const exp = r.classes.filter((c) => c.category === "likely-exploitable");

const themes = [
  ["IP-canon (hex 0x...)", (c) => /0x[0-9a-f]+/i.test(c.representativeInput)],
  ["IP-canon (octal 0NNN)", (c) => /\b0\d{2,}\.\d/.test(c.representativeInput)],
  ["IP-canon (dotless decimal)", (c) => /\/\/\d{8,}\b/.test(c.representativeInput)],
  ["IP-canon (shorthand 127.1)", (c) => /\/\/127\.\d+\b/.test(c.representativeInput) && !/\/\/127\.0\.0\.1\b/.test(c.representativeInput)],
  ["IPv6-mapped loopback", (c) => /\[::ffff:127/i.test(c.representativeInput)],
  ["IDN/fullwidth", (c) => /[ｅｖｉｌ。．]/.test(c.representativeInput)],
  ["Tab/CR/LF in scheme", (c) => /^[a-z]*[\t\r\n][a-z]*:/i.test(c.representativeInput)],
  ["Empty/triple-slash authority", (c) => /^[a-z]+:\/\/\//i.test(c.representativeInput)],
  ["Single-slash scheme", (c) => /^[a-z]+:\/[^/]/i.test(c.representativeInput)],
  ["Userinfo @evil", (c) => /\.com@/.test(c.representativeInput)],
  ["Backslash-slash", (c) => /\\/.test(c.representativeInput)],
];

console.log("Themes (likely-exploitable only):");
const claimed = new Set();
for (const [name, fn] of themes) {
  const hits = exp.filter(fn);
  const total = hits.reduce((s, c) => s + c.count, 0);
  console.log(`  ${String(hits.length).padStart(3)} classes / ${String(total).padStart(4)} hits | ${name}`);
  for (const h of hits) claimed.add(h.signature);
}
const unclassed = exp.filter((c) => !claimed.has(c.signature));
console.log(`  ${String(unclassed.length).padStart(3)} classes / ${String(unclassed.reduce((s, c) => s + c.count, 0)).padStart(4)} hits | (other)`);
