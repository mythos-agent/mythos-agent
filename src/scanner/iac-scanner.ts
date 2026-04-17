import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface IacRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe?: string;
  filePatterns: string[];
  check: (content: string, lines: string[]) => IacMatch[];
}

interface IacMatch {
  line: number;
  snippet: string;
}

const IAC_RULES: IacRule[] = [
  // === Dockerfile ===
  {
    id: "docker-root-user",
    title: "Docker: Running as Root",
    description: "Container runs as root by default. Add 'USER nonroot' to reduce attack surface.",
    severity: "high",
    cwe: "CWE-250",
    filePatterns: ["**/Dockerfile*"],
    check: (content, lines) => {
      // Check if there's no USER instruction (other than root)
      const hasUser = lines.some((l) => /^USER\s+(?!root)/i.test(l.trim()));
      if (hasUser) return [];
      // Find the FROM line to attach the finding to
      for (let i = 0; i < lines.length; i++) {
        if (/^FROM\s/i.test(lines[i].trim())) {
          return [{ line: i + 1, snippet: lines[i].trim() }];
        }
      }
      return [];
    },
  },
  {
    id: "docker-latest-tag",
    title: "Docker: Using 'latest' Tag",
    description: "Using 'latest' tag makes builds non-reproducible. Pin to a specific version.",
    severity: "medium",
    filePatterns: ["**/Dockerfile*"],
    check: (_content, lines) => {
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (
          /^FROM\s+\S+:latest/i.test(lines[i].trim()) ||
          /^FROM\s+[^:@\s]+\s/i.test(lines[i].trim())
        ) {
          // No tag or :latest
          if (!lines[i].includes(":") && !lines[i].includes("@")) {
            matches.push({ line: i + 1, snippet: lines[i].trim() });
          } else if (lines[i].includes(":latest")) {
            matches.push({ line: i + 1, snippet: lines[i].trim() });
          }
        }
      }
      return matches;
    },
  },
  {
    id: "docker-add-instead-of-copy",
    title: "Docker: Use COPY Instead of ADD",
    description:
      "ADD has implicit tar extraction and URL fetching which can be exploited. Use COPY unless you specifically need ADD features.",
    severity: "low",
    filePatterns: ["**/Dockerfile*"],
    check: (_content, lines) => {
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (/^ADD\s/i.test(lines[i].trim()) && !lines[i].includes("http")) {
          matches.push({ line: i + 1, snippet: lines[i].trim() });
        }
      }
      return matches;
    },
  },
  {
    id: "docker-secret-in-env",
    title: "Docker: Secret in ENV/ARG",
    description:
      "Secrets in ENV or ARG are visible in image history. Use Docker secrets or build-time mounts.",
    severity: "high",
    cwe: "CWE-798",
    filePatterns: ["**/Dockerfile*"],
    check: (_content, lines) => {
      const matches: IacMatch[] = [];
      const secretWords = /(?:password|secret|key|token|credential|api_key)/i;
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (/^(?:ENV|ARG)\s/i.test(trimmed) && secretWords.test(trimmed)) {
          matches.push({ line: i + 1, snippet: trimmed });
        }
      }
      return matches;
    },
  },
  {
    id: "docker-expose-all",
    title: "Docker: Exposing Sensitive Port",
    description:
      "Exposing port 22 (SSH), 3306 (MySQL), 5432 (Postgres), or 6379 (Redis) directly is risky in production.",
    severity: "medium",
    filePatterns: ["**/Dockerfile*"],
    check: (_content, lines) => {
      const matches: IacMatch[] = [];
      const riskyPorts = ["22", "3306", "5432", "6379", "27017"];
      for (let i = 0; i < lines.length; i++) {
        if (/^EXPOSE\s/i.test(lines[i].trim())) {
          for (const port of riskyPorts) {
            if (lines[i].includes(port)) {
              matches.push({ line: i + 1, snippet: lines[i].trim() });
              break;
            }
          }
        }
      }
      return matches;
    },
  },

  // === Terraform ===
  {
    id: "tf-public-access",
    title: "Terraform: Public Access Enabled",
    description: "Resource allows public access (0.0.0.0/0). Restrict to specific IP ranges.",
    severity: "high",
    cwe: "CWE-284",
    filePatterns: ["**/*.tf"],
    check: (_content, lines) => {
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes("0.0.0.0/0") || lines[i].includes("::/0")) {
          matches.push({ line: i + 1, snippet: lines[i].trim() });
        }
      }
      return matches;
    },
  },
  {
    id: "tf-hardcoded-secret",
    title: "Terraform: Hardcoded Secret in Config",
    description:
      "Secret appears hardcoded in Terraform config. Use variables or a secrets manager.",
    severity: "critical",
    cwe: "CWE-798",
    filePatterns: ["**/*.tf"],
    check: (_content, lines) => {
      const matches: IacMatch[] = [];
      const secretPattern = /(?:password|secret_key|access_key|token)\s*=\s*"[^"]{8,}"/i;
      for (let i = 0; i < lines.length; i++) {
        if (secretPattern.test(lines[i]) && !lines[i].includes("var.")) {
          matches.push({ line: i + 1, snippet: lines[i].trim() });
        }
      }
      return matches;
    },
  },
  {
    id: "tf-unencrypted-storage",
    title: "Terraform: Unencrypted Storage",
    description: "Storage resource without encryption enabled. Enable encryption at rest.",
    severity: "high",
    filePatterns: ["**/*.tf"],
    check: (content, lines) => {
      const matches: IacMatch[] = [];
      // Look for S3 buckets, EBS volumes, RDS without encryption
      if (content.includes("aws_s3_bucket") && !content.includes("server_side_encryption")) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes("aws_s3_bucket")) {
            matches.push({ line: i + 1, snippet: lines[i].trim() });
          }
        }
      }
      if (content.includes("aws_ebs_volume") && !content.includes("encrypted = true")) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes("aws_ebs_volume")) {
            matches.push({ line: i + 1, snippet: lines[i].trim() });
          }
        }
      }
      return matches;
    },
  },
  {
    id: "tf-open-security-group",
    title: "Terraform: Open Security Group",
    description:
      "Security group allows all inbound traffic. Restrict to needed ports and IP ranges.",
    severity: "critical",
    cwe: "CWE-284",
    filePatterns: ["**/*.tf"],
    check: (_content, lines) => {
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        // protocol = "-1" means all traffic
        if (
          /protocol\s*=\s*"-1"/.test(lines[i]) ||
          /from_port\s*=\s*0.*to_port\s*=\s*65535/.test(lines[i])
        ) {
          matches.push({ line: i + 1, snippet: lines[i].trim() });
        }
      }
      return matches;
    },
  },

  // === Kubernetes ===
  {
    id: "k8s-privileged",
    title: "K8s: Privileged Container",
    description:
      "Container running in privileged mode has full host access. Remove privileged: true.",
    severity: "critical",
    cwe: "CWE-250",
    filePatterns: ["**/*.yml", "**/*.yaml"],
    check: (content, lines) => {
      if (!content.includes("kind:") || !content.includes("apiVersion:")) return [];
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (/privileged:\s*true/i.test(lines[i])) {
          matches.push({ line: i + 1, snippet: lines[i].trim() });
        }
      }
      return matches;
    },
  },
  {
    id: "k8s-run-as-root",
    title: "K8s: Running as Root",
    description: "Container can run as root. Set runAsNonRoot: true in securityContext.",
    severity: "high",
    cwe: "CWE-250",
    filePatterns: ["**/*.yml", "**/*.yaml"],
    check: (content, lines) => {
      if (!content.includes("kind:") || !content.includes("containers:")) return [];
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (/runAsUser:\s*0/.test(lines[i])) {
          matches.push({ line: i + 1, snippet: lines[i].trim() });
        }
      }
      // Also flag if no securityContext at all in a deployment
      if (content.includes("kind: Deployment") && !content.includes("securityContext")) {
        for (let i = 0; i < lines.length; i++) {
          if (/kind:\s*Deployment/.test(lines[i])) {
            matches.push({ line: i + 1, snippet: lines[i].trim() + " (missing securityContext)" });
            break;
          }
        }
      }
      return matches;
    },
  },
  {
    id: "k8s-no-resource-limits",
    title: "K8s: No Resource Limits",
    description:
      "Container has no resource limits. Set CPU/memory limits to prevent resource exhaustion.",
    severity: "medium",
    filePatterns: ["**/*.yml", "**/*.yaml"],
    check: (content, lines) => {
      if (!content.includes("containers:") || !content.includes("kind:")) return [];
      if (content.includes("limits:")) return [];
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (/^\s*containers:/.test(lines[i])) {
          matches.push({ line: i + 1, snippet: lines[i].trim() + " (no resource limits)" });
        }
      }
      return matches;
    },
  },
  {
    id: "k8s-host-network",
    title: "K8s: Host Network Enabled",
    description:
      "Pod uses host network namespace. This bypasses network policies and exposes host services.",
    severity: "high",
    filePatterns: ["**/*.yml", "**/*.yaml"],
    check: (content, lines) => {
      if (!content.includes("kind:")) return [];
      const matches: IacMatch[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (/hostNetwork:\s*true/i.test(lines[i])) {
          matches.push({ line: i + 1, snippet: lines[i].trim() });
        }
      }
      return matches;
    },
  },
];

export interface IacScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class IacScanner {
  async scan(projectPath: string): Promise<IacScanResult> {
    // Collect all unique file patterns
    const allPatterns = [...new Set(IAC_RULES.flatMap((r) => r.filePatterns))];

    const files = await glob(allPatterns, {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
      nodir: true,
    });

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of IAC_RULES) {
        // Check if file matches rule patterns
        const matches = rule.filePatterns.some((p) => {
          const simplePattern = p.replace("**/", "").replace("*", "");
          return relativePath.includes(simplePattern) || relativePath.endsWith(simplePattern);
        });
        if (!matches) continue;

        const iacMatches = rule.check(content, lines);
        for (const match of iacMatches) {
          findings.push({
            id: `IAC-${String(idCounter++).padStart(4, "0")}`,
            rule: `iac:${rule.id}`,
            title: rule.title,
            description: rule.description,
            severity: rule.severity,
            category: "iac",
            cwe: rule.cwe,
            confidence: "high",
            location: {
              file: relativePath,
              line: match.line,
              snippet: match.snippet,
            },
          });
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
