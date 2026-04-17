import path from "node:path";
import fs from "node:fs";
import chalk from "chalk";
import ora from "ora";
import Anthropic from "@anthropic-ai/sdk";
import { loadConfig } from "../../config/config.js";
import { parseCodebase } from "../../analysis/code-parser.js";
import { mapEndpoints, assessEndpointSecurity } from "../../analysis/endpoint-mapper.js";
import { mapServices } from "../../analysis/service-mapper.js";

interface ThreatModelOptions {
  path?: string;
  json?: boolean;
}

const STRIDE_SYSTEM = `You are a threat modeling expert. Given a codebase architecture, generate a STRIDE threat model.

STRIDE categories:
- **S**poofing: Can an attacker impersonate a user or service?
- **T**ampering: Can data be modified in transit or at rest?
- **R**epudiation: Can an attacker deny their actions?
- **I**nformation Disclosure: Can sensitive data leak?
- **D**enial of Service: Can the system be overwhelmed?
- **E**levation of Privilege: Can a user gain unauthorized access?

Output JSON:
{
  "summary": "Brief architecture description",
  "components": [
    {
      "name": "Component name",
      "type": "web-app|api|database|cache|queue|service",
      "description": "What it does",
      "threats": [
        {
          "category": "S|T|R|I|D|E",
          "threat": "Specific threat description",
          "impact": "high|medium|low",
          "mitigation": "How to mitigate"
        }
      ]
    }
  ],
  "dataFlows": [
    {
      "from": "Component A",
      "to": "Component B",
      "data": "What data flows",
      "threats": ["Threat 1", "Threat 2"]
    }
  ],
  "trustBoundaries": [
    {
      "name": "Boundary name",
      "inside": ["Component A"],
      "outside": ["Component B"],
      "risks": ["Risk description"]
    }
  ]
}`;

export async function threatModelCommand(options: ThreatModelOptions) {
  const projectPath = path.resolve(options.path || ".");
  const config = loadConfig(projectPath);

  console.log(chalk.bold("\n🛡️  sphinx-agent threat-model — STRIDE Analysis\n"));

  const spinner = ora("Analyzing architecture...").start();

  // Gather architecture info
  const codebase = await parseCodebase(projectPath);
  const endpoints = mapEndpoints(codebase);
  const assessment = assessEndpointSecurity(endpoints);
  const services = await mapServices(projectPath);

  const archSummary = [
    `Functions: ${codebase.functions.length}`,
    `Routes: ${codebase.routes.length}`,
    `Endpoints: ${endpoints.length} (${assessment.authenticated} authenticated, ${assessment.unauthenticated} unauthenticated)`,
    `Services: ${services.services.length}`,
    `Trust boundaries: ${services.trustBoundaries.length}`,
    `Tech: ${[...new Set(codebase.imports.map((i) => i.source).filter((s) => !s.startsWith(".")))].slice(0, 15).join(", ")}`,
  ].join("\n");

  const endpointList = endpoints
    .slice(0, 20)
    .map((e) => `${e.method} ${e.path} — auth:${e.hasAuth} risk:${e.riskLevel}`)
    .join("\n");

  const serviceList = services.services
    .map((s) => `${s.name} (${s.type}) — ports:${s.ports.join(",") || "none"}`)
    .join("\n");

  spinner.text = "Generating STRIDE threat model...";

  if (!config.apiKey) {
    spinner.stop();
    // Basic non-AI threat model
    renderBasicThreatModel(endpoints, services, projectPath, options.json);
    return;
  }

  try {
    const client = new Anthropic({ apiKey: config.apiKey });
    const response = await client.messages.create({
      model: config.model,
      max_tokens: 8192,
      system: STRIDE_SYSTEM,
      messages: [
        {
          role: "user",
          content: `Generate a STRIDE threat model for this application:\n\n## Architecture\n${archSummary}\n\n## Endpoints\n${endpointList}\n\n## Services\n${serviceList || "No services detected (single application)"}`,
        },
      ],
    });

    spinner.stop();

    const text = response.content.find((b) => b.type === "text");
    if (!text || text.type !== "text") {
      renderBasicThreatModel(endpoints, services, projectPath, options.json);
      return;
    }

    const jsonMatch = text.text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.log(text.text);
      return;
    }

    const model = JSON.parse(jsonMatch[0]);

    if (options.json) {
      console.log(JSON.stringify(model, null, 2));
      return;
    }

    // Render threat model
    console.log(chalk.dim(`  ${model.summary || "Application threat model"}\n`));

    for (const comp of model.components || []) {
      console.log(chalk.bold(`  📦 ${comp.name}`) + chalk.dim(` (${comp.type})`));
      if (comp.description) console.log(chalk.dim(`     ${comp.description}`));

      for (const threat of comp.threats || []) {
        const icons: Record<string, string> = {
          S: "🎭",
          T: "✏️",
          R: "📝",
          I: "👁️",
          D: "💥",
          E: "⬆️",
        };
        const icon = icons[threat.category as string] || "⚠️";
        const color =
          threat.impact === "high"
            ? chalk.red
            : threat.impact === "medium"
              ? chalk.yellow
              : chalk.blue;
        console.log(`     ${icon} ${color(`[${threat.category}]`)} ${threat.threat}`);
        console.log(chalk.dim(`        Mitigation: ${threat.mitigation}`));
      }
      console.log();
    }

    if (model.dataFlows?.length > 0) {
      console.log(chalk.bold("  📊 Data Flows\n"));
      for (const flow of model.dataFlows) {
        console.log(`     ${flow.from} → ${flow.to}: ${chalk.dim(flow.data)}`);
        for (const t of flow.threats || []) console.log(chalk.dim(`       ⚠️ ${t}`));
      }
      console.log();
    }

    // Save to file
    const outputPath = path.join(projectPath, ".sphinx", "threat-model.json");
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(model, null, 2));
    console.log(chalk.dim(`  Saved to ${outputPath}\n`));
  } catch (err) {
    spinner.fail(`Threat model failed: ${err instanceof Error ? err.message : "error"}`);
    renderBasicThreatModel(endpoints, services, projectPath, options.json);
  }
}

function renderBasicThreatModel(
  endpoints: any[],
  services: any,
  projectPath: string,
  json?: boolean
) {
  const threats = [];

  // Auto-generate basic threats from endpoints
  for (const ep of endpoints) {
    if (!ep.hasAuth && ep.riskLevel === "high") {
      threats.push({
        category: "S",
        component: ep.path,
        threat: `Unauthenticated ${ep.method} endpoint`,
        impact: "high",
      });
    }
    if (ep.method === "POST" || ep.method === "PUT") {
      threats.push({
        category: "T",
        component: ep.path,
        threat: "Data tampering via API",
        impact: "medium",
      });
    }
  }

  if (json) {
    console.log(JSON.stringify({ threats }, null, 2));
  } else {
    console.log(chalk.bold("\n  Basic Threat Model (add API key for full STRIDE analysis)\n"));
    for (const t of threats.slice(0, 15)) {
      console.log(`  [${t.category}] ${t.component} — ${t.threat}`);
    }
    console.log();
  }
}
