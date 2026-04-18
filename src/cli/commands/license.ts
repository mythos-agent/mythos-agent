import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import {
  discoverLockfiles,
  parseLockfile,
  type Dependency,
} from "../../scanner/lockfile-parsers.js";

interface LicenseInfo {
  name: string;
  version: string;
  license: string;
  risk: "ok" | "copyleft" | "unknown" | "restricted";
}

interface LicenseOptions {
  path?: string;
  json?: boolean;
  deny?: string;
}

const COPYLEFT_LICENSES = [
  "GPL-2.0",
  "GPL-3.0",
  "AGPL-3.0",
  "LGPL-2.1",
  "LGPL-3.0",
  "GPL-2.0-only",
  "GPL-3.0-only",
  "AGPL-3.0-only",
  "GPL-2.0-or-later",
  "GPL-3.0-or-later",
  "EUPL-1.2",
  "MPL-2.0",
  "CPAL-1.0",
  "OSL-3.0",
];

const PERMISSIVE_LICENSES = [
  "MIT",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "0BSD",
  "CC0-1.0",
  "Unlicense",
  "WTFPL",
  "Zlib",
  "BlueOak-1.0.0",
  "PSF-2.0",
];

export async function licenseCommand(options: LicenseOptions) {
  const projectPath = path.resolve(options.path || ".");
  const denyList = options.deny ? options.deny.split(",").map((s) => s.trim()) : [];

  // Discover dependencies
  const lockfiles = discoverLockfiles(projectPath);
  if (lockfiles.length === 0) {
    console.log(chalk.yellow("\n⚠️  No lockfiles found.\n"));
    return;
  }

  const allDeps: Dependency[] = [];
  for (const lf of lockfiles) {
    allDeps.push(...parseLockfile(lf));
  }

  // Deduplicate
  const seen = new Set<string>();
  const deps = allDeps.filter((d) => {
    const key = `${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Read licenses from node_modules (npm/yarn)
  const licenses: LicenseInfo[] = [];
  for (const dep of deps) {
    const license = readLicense(dep, projectPath);
    licenses.push(license);
  }

  if (options.json) {
    console.log(JSON.stringify(licenses, null, 2));
    return;
  }

  // Summary
  const copyleft = licenses.filter((l) => l.risk === "copyleft");
  const unknown = licenses.filter((l) => l.risk === "unknown");
  const denied =
    denyList.length > 0 ? licenses.filter((l) => denyList.some((d) => l.license.includes(d))) : [];
  const ok = licenses.filter((l) => l.risk === "ok");

  console.log(chalk.bold("\n📜 shedu license\n"));
  console.log(chalk.dim(`  ${licenses.length} dependencies analyzed\n`));

  console.log(
    `  ${chalk.green(`${ok.length} permissive`)} | ${chalk.yellow(`${copyleft.length} copyleft`)} | ${chalk.red(`${unknown.length} unknown`)}${denied.length > 0 ? ` | ${chalk.bgRed.white(` ${denied.length} denied `)}` : ""}\n`
  );

  // Show copyleft
  if (copyleft.length > 0) {
    console.log(chalk.yellow.bold("  Copyleft licenses (may require source disclosure):\n"));
    for (const l of copyleft) {
      console.log(`    ${chalk.yellow("⚠")} ${l.name}@${l.version} — ${chalk.yellow(l.license)}`);
    }
    console.log();
  }

  // Show unknown
  if (unknown.length > 0) {
    console.log(chalk.red.bold("  Unknown licenses (review manually):\n"));
    for (const l of unknown.slice(0, 20)) {
      console.log(
        `    ${chalk.red("?")} ${l.name}@${l.version} — ${chalk.red(l.license || "UNLICENSED")}`
      );
    }
    if (unknown.length > 20) console.log(chalk.dim(`    ...and ${unknown.length - 20} more`));
    console.log();
  }

  // Show denied
  if (denied.length > 0) {
    console.log(chalk.bgRed.white.bold("  DENIED licenses:\n"));
    for (const l of denied) {
      console.log(`    ${chalk.red("✗")} ${l.name}@${l.version} — ${chalk.red(l.license)}`);
    }
    console.log();
    process.exit(1);
  }
}

function readLicense(dep: Dependency, projectPath: string): LicenseInfo {
  // Try reading from node_modules package.json
  const pkgPath = path.join(projectPath, "node_modules", dep.name, "package.json");

  let license = "UNKNOWN";

  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
      license = typeof pkg.license === "string" ? pkg.license : pkg.license?.type || "UNKNOWN";
    } catch {
      // parse error
    }
  }

  const risk = classifyLicense(license);

  return {
    name: dep.name,
    version: dep.version,
    license,
    risk,
  };
}

function classifyLicense(license: string): "ok" | "copyleft" | "unknown" | "restricted" {
  const upper = license.toUpperCase();

  if (upper === "UNKNOWN" || upper === "UNLICENSED" || !license) return "unknown";

  if (PERMISSIVE_LICENSES.some((l) => upper.includes(l.toUpperCase()))) return "ok";
  if (COPYLEFT_LICENSES.some((l) => upper.includes(l.toUpperCase()))) return "copyleft";

  // Check common patterns
  if (
    upper.includes("MIT") ||
    upper.includes("BSD") ||
    upper.includes("ISC") ||
    upper.includes("APACHE")
  )
    return "ok";
  if (upper.includes("GPL") || upper.includes("AGPL")) return "copyleft";

  return "unknown";
}
