import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { glob } from "glob";

export interface Service {
  name: string;
  type: "container" | "function" | "process";
  image?: string;
  ports: number[];
  environment: Record<string, string>;
  dependsOn: string[];
  volumes: string[];
  file: string;
}

export interface ServiceConnection {
  from: string;
  to: string;
  protocol: string;
  port?: number;
  description: string;
}

export interface TrustBoundary {
  name: string;
  services: string[];
  exposure: "public" | "internal" | "private";
  risks: string[];
}

export interface ServiceMap {
  services: Service[];
  connections: ServiceConnection[];
  trustBoundaries: TrustBoundary[];
}

/**
 * Map all services and their connections from infrastructure definitions.
 */
export async function mapServices(projectPath: string): Promise<ServiceMap> {
  const services: Service[] = [];
  const connections: ServiceConnection[] = [];

  // Parse docker-compose files
  const composeFiles = await glob(
    ["docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml"],
    { cwd: projectPath, absolute: true }
  );
  for (const file of composeFiles) {
    const parsed = parseDockerCompose(file);
    services.push(...parsed.services);
    connections.push(...parsed.connections);
  }

  // Parse Kubernetes manifests
  const k8sFiles = await glob(
    ["k8s/**/*.yml", "k8s/**/*.yaml", "kubernetes/**/*.yml", "manifests/**/*.yml", "deploy/**/*.yml"],
    { cwd: projectPath, absolute: true, ignore: ["node_modules/**"] }
  );
  for (const file of k8sFiles) {
    const parsed = parseK8sManifest(file, projectPath);
    services.push(...parsed.services);
    connections.push(...parsed.connections);
  }

  // Infer connections from environment variables
  connections.push(...inferConnections(services));

  // Build trust boundaries
  const trustBoundaries = buildTrustBoundaries(services, connections);

  return { services, connections, trustBoundaries };
}

function parseDockerCompose(
  filePath: string
): { services: Service[]; connections: ServiceConnection[] } {
  const services: Service[] = [];
  const connections: ServiceConnection[] = [];
  const relPath = path.basename(filePath);

  try {
    const content = fs.readFileSync(filePath, "utf-8");
    const doc = yaml.load(content) as Record<string, unknown>;
    const svcs = (doc?.services || {}) as Record<string, Record<string, unknown>>;

    for (const [name, config] of Object.entries(svcs)) {
      const ports: number[] = [];
      const rawPorts = (config.ports || []) as string[];
      for (const p of rawPorts) {
        const match = String(p).match(/:(\d+)/);
        if (match) ports.push(parseInt(match[1]));
      }

      const env: Record<string, string> = {};
      const rawEnv = config.environment as string[] | Record<string, string> | undefined;
      if (Array.isArray(rawEnv)) {
        for (const e of rawEnv) {
          const [k, ...v] = e.split("=");
          env[k] = v.join("=");
        }
      } else if (rawEnv && typeof rawEnv === "object") {
        Object.assign(env, rawEnv);
      }

      const dependsOn = Array.isArray(config.depends_on)
        ? config.depends_on as string[]
        : typeof config.depends_on === "object" && config.depends_on
          ? Object.keys(config.depends_on)
          : [];

      services.push({
        name,
        type: "container",
        image: config.image as string | undefined,
        ports,
        environment: env,
        dependsOn,
        volumes: ((config.volumes || []) as string[]).map(String),
        file: relPath,
      });

      // Explicit depends_on creates connections
      for (const dep of dependsOn) {
        connections.push({
          from: name,
          to: dep,
          protocol: "tcp",
          description: `${name} depends on ${dep}`,
        });
      }
    }
  } catch {
    // ignore parse errors
  }

  return { services, connections };
}

function parseK8sManifest(
  filePath: string,
  projectPath: string
): { services: Service[]; connections: ServiceConnection[] } {
  const services: Service[] = [];
  const connections: ServiceConnection[] = [];
  const relPath = path.relative(projectPath, filePath);

  try {
    const content = fs.readFileSync(filePath, "utf-8");
    const docs = yaml.loadAll(content) as Array<Record<string, unknown>>;

    for (const doc of docs) {
      if (!doc || !doc.kind) continue;

      if (doc.kind === "Deployment" || doc.kind === "StatefulSet" || doc.kind === "DaemonSet") {
        const meta = (doc.metadata || {}) as Record<string, string>;
        const spec = (doc.spec || {}) as Record<string, unknown>;
        const template = (spec.template || {}) as Record<string, unknown>;
        const podSpec = (template.spec || {}) as Record<string, unknown>;
        const containers = (podSpec.containers || []) as Array<Record<string, unknown>>;

        for (const container of containers) {
          const ports: number[] = [];
          for (const p of (container.ports || []) as Array<Record<string, number>>) {
            if (p.containerPort) ports.push(p.containerPort);
          }

          const env: Record<string, string> = {};
          for (const e of (container.env || []) as Array<Record<string, string>>) {
            if (e.name && e.value) env[e.name] = e.value;
          }

          services.push({
            name: meta.name || container.name as string || "unknown",
            type: "container",
            image: container.image as string | undefined,
            ports,
            environment: env,
            dependsOn: [],
            volumes: [],
            file: relPath,
          });
        }
      }

      if (doc.kind === "Service") {
        const meta = (doc.metadata || {}) as Record<string, string>;
        const spec = (doc.spec || {}) as Record<string, unknown>;
        const serviceType = spec.type as string || "ClusterIP";
        const servicePorts = (spec.ports || []) as Array<Record<string, number>>;

        for (const p of servicePorts) {
          if (p.targetPort) {
            connections.push({
              from: `k8s-service:${meta.name}`,
              to: meta.name || "unknown",
              protocol: "tcp",
              port: p.targetPort,
              description: `K8s ${serviceType} service → port ${p.targetPort}`,
            });
          }
        }
      }
    }
  } catch {
    // ignore
  }

  return { services, connections };
}

/**
 * Infer service connections from environment variables.
 * e.g., DATABASE_URL=postgres://db:5432 means this service connects to 'db'.
 */
function inferConnections(services: Service[]): ServiceConnection[] {
  const connections: ServiceConnection[] = [];
  const serviceNames = new Set(services.map((s) => s.name));

  for (const svc of services) {
    for (const [key, value] of Object.entries(svc.environment)) {
      // Check if env var references another service
      for (const otherName of serviceNames) {
        if (otherName === svc.name) continue;
        if (value.includes(otherName)) {
          const protocol = key.toLowerCase().includes("redis")
            ? "redis"
            : key.toLowerCase().includes("mongo")
              ? "mongodb"
              : key.toLowerCase().includes("postgres") || key.toLowerCase().includes("database")
                ? "postgresql"
                : key.toLowerCase().includes("amqp") || key.toLowerCase().includes("rabbit")
                  ? "amqp"
                  : "tcp";

          connections.push({
            from: svc.name,
            to: otherName,
            protocol,
            description: `${svc.name} references ${otherName} via ${key}`,
          });
        }
      }

      // Check for URL patterns
      const urlMatch = value.match(/(?:https?|postgres|mysql|mongodb|redis|amqp):\/\/([^:\/\s]+)/);
      if (urlMatch && !serviceNames.has(urlMatch[1])) {
        connections.push({
          from: svc.name,
          to: urlMatch[1],
          protocol: value.split("://")[0],
          description: `${svc.name} connects to external ${urlMatch[1]} via ${key}`,
        });
      }
    }
  }

  return connections;
}

/**
 * Identify trust boundaries between service groups.
 */
function buildTrustBoundaries(
  services: Service[],
  connections: ServiceConnection[]
): TrustBoundary[] {
  const boundaries: TrustBoundary[] = [];

  // Public boundary: services with exposed ports
  const publicServices = services.filter((s) => s.ports.length > 0);
  if (publicServices.length > 0) {
    const risks: string[] = [];
    for (const svc of publicServices) {
      if (svc.ports.some((p) => [22, 3306, 5432, 6379, 27017].includes(p))) {
        risks.push(`${svc.name} exposes sensitive port(s): ${svc.ports.join(", ")}`);
      }
    }

    boundaries.push({
      name: "Public-facing services",
      services: publicServices.map((s) => s.name),
      exposure: "public",
      risks,
    });
  }

  // Internal boundary: services with no exposed ports
  const internalServices = services.filter((s) => s.ports.length === 0);
  if (internalServices.length > 0) {
    boundaries.push({
      name: "Internal services",
      services: internalServices.map((s) => s.name),
      exposure: "internal",
      risks: [],
    });
  }

  // Database boundary
  const dbServices = services.filter(
    (s) => s.image && /postgres|mysql|mongo|redis|mariadb/i.test(s.image)
  );
  if (dbServices.length > 0) {
    const risks: string[] = [];
    for (const db of dbServices) {
      if (db.ports.length > 0) {
        risks.push(`${db.name} database port exposed publicly`);
      }
      const hasDefaultPassword = Object.values(db.environment).some(
        (v) => /password|123|admin|root|default/i.test(v)
      );
      if (hasDefaultPassword) {
        risks.push(`${db.name} may have default/weak credentials`);
      }
    }

    boundaries.push({
      name: "Data layer",
      services: dbServices.map((s) => s.name),
      exposure: "private",
      risks,
    });
  }

  return boundaries;
}
