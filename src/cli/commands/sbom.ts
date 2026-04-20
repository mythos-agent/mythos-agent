import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import {
  discoverLockfiles,
  parseLockfile,
  type Dependency,
} from "../../scanner/lockfile-parsers.js";
import { VERSION } from "../../version.js";

interface SbomOptions {
  path?: string;
  format: string;
  output?: string;
}

export async function sbomCommand(options: SbomOptions) {
  const projectPath = path.resolve(options.path || ".");
  const lockfiles = discoverLockfiles(projectPath);

  if (lockfiles.length === 0) {
    console.log(chalk.yellow("\n⚠️  No lockfiles found. Cannot generate SBOM.\n"));
    return;
  }

  // Parse all dependencies
  const allDeps: Dependency[] = [];
  for (const lockfile of lockfiles) {
    allDeps.push(...parseLockfile(lockfile));
  }

  // Deduplicate
  const seen = new Set<string>();
  const deps = allDeps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const format = options.format;
  let sbom: string;

  if (format === "spdx") {
    sbom = generateSpdx(deps, projectPath);
  } else {
    sbom = generateCycloneDx(deps, projectPath);
  }

  if (options.output) {
    const outputPath = path.resolve(options.output);
    fs.writeFileSync(outputPath, sbom, "utf-8");
    console.log(chalk.green(`\n✅ SBOM (${format.toUpperCase()}) saved to ${outputPath}`));
  } else {
    console.log(sbom);
  }

  console.log(chalk.dim(`\n  ${deps.length} components from ${lockfiles.length} lockfile(s)\n`));
}

function generateCycloneDx(deps: Dependency[], projectPath: string): string {
  const projectName = path.basename(projectPath);

  const components = deps.map((d) => ({
    type: "library",
    name: d.name,
    version: d.version,
    purl: `pkg:${d.ecosystem.toLowerCase()}/${encodeURIComponent(d.name)}@${d.version}`,
    "bom-ref": `${d.ecosystem}:${d.name}@${d.version}`,
  }));

  return JSON.stringify(
    {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: "mythos-agent", name: "mythos-agent", version: VERSION }],
        component: {
          type: "application",
          name: projectName,
          "bom-ref": projectName,
        },
      },
      components,
    },
    null,
    2
  );
}

function generateSpdx(deps: Dependency[], projectPath: string): string {
  const projectName = path.basename(projectPath);
  const timestamp = new Date().toISOString();

  const packages = deps.map((d, i) => ({
    SPDXID: `SPDXRef-Package-${i + 1}`,
    name: d.name,
    versionInfo: d.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: `pkg:${d.ecosystem.toLowerCase()}/${encodeURIComponent(d.name)}@${d.version}`,
      },
    ],
  }));

  return JSON.stringify(
    {
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: `${projectName}-sbom`,
      documentNamespace: `https://mythos-agent.com/sbom/${projectName}/${timestamp}`,
      creationInfo: {
        created: timestamp,
        creators: [`Tool: mythos-agent-${VERSION}`],
      },
      packages: [
        {
          SPDXID: "SPDXRef-RootPackage",
          name: projectName,
          versionInfo: "1.0.0",
          downloadLocation: "NOASSERTION",
          filesAnalyzed: false,
        },
        ...packages,
      ],
      relationships: packages.map((p) => ({
        spdxElementId: "SPDXRef-RootPackage",
        relationshipType: "DEPENDS_ON",
        relatedSpdxElement: p.SPDXID,
      })),
    },
    null,
    2
  );
}
