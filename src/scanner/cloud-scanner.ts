import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface CloudRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  provider: "aws" | "azure" | "gcp" | "general";
  filePatterns: string[];
  patterns: RegExp[];
}

const CLOUD_RULES: CloudRule[] = [
  // === AWS ===
  {
    id: "aws-s3-public",
    title: "AWS: S3 Bucket with Public Access",
    description: "S3 bucket configured with public ACL. Data is accessible to anyone on the internet.",
    severity: "critical",
    cwe: "CWE-284",
    provider: "aws",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml", "**/*.yaml", "**/*.ts", "**/*.py"],
    patterns: [
      /acl\s*[:=]\s*["']public-read(?:-write)?["']/gi,
      /PublicAccessBlockConfiguration.*BlockPublicAcls.*false/gi,
      /block_public_acls\s*=\s*false/gi,
    ],
  },
  {
    id: "aws-iam-wildcard",
    title: "AWS: IAM Policy with Wildcard Permissions",
    description: "IAM policy grants '*' action on '*' resource. This is overprivileged and violates least privilege.",
    severity: "critical",
    cwe: "CWE-250",
    provider: "aws",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml", "**/*.yaml"],
    patterns: [
      /"Action"\s*:\s*"\*".*"Resource"\s*:\s*"\*"/gi,
      /actions?\s*[:=]\s*\[\s*["']\*["']\s*\]/gi,
      /Effect.*Allow.*Action.*\*.*Resource.*\*/gi,
    ],
  },
  {
    id: "aws-sg-open",
    title: "AWS: Security Group Open to World",
    description: "Security group allows inbound traffic from 0.0.0.0/0 on sensitive ports.",
    severity: "high",
    cwe: "CWE-284",
    provider: "aws",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml", "**/*.yaml"],
    patterns: [
      /cidr_blocks\s*[:=]\s*\[\s*["']0\.0\.0\.0\/0["']/gi,
      /CidrIp.*0\.0\.0\.0\/0/gi,
      /ingress.*0\.0\.0\.0\/0/gi,
    ],
  },
  {
    id: "aws-rds-no-encryption",
    title: "AWS: RDS Without Encryption at Rest",
    description: "RDS database instance without encryption. Sensitive data stored unencrypted.",
    severity: "high",
    cwe: "CWE-311",
    provider: "aws",
    filePatterns: ["**/*.tf", "**/*.json"],
    patterns: [
      /aws_db_instance.*(?:(?!storage_encrypted\s*=\s*true)[\s\S]){0,200}}/gi,
      /StorageEncrypted.*false/gi,
    ],
  },
  {
    id: "aws-lambda-secrets",
    title: "AWS: Secrets in Lambda Environment Variables",
    description: "Sensitive values hardcoded in Lambda environment configuration. Use Secrets Manager or SSM Parameter Store.",
    severity: "high",
    cwe: "CWE-798",
    provider: "aws",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml", "**/*.yaml"],
    patterns: [
      /environment\s*\{[^}]*(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*[:=]\s*["'][^"']+["']/gi,
    ],
  },

  // === Azure ===
  {
    id: "azure-storage-public",
    title: "Azure: Storage Account with Public Blob Access",
    description: "Azure storage account allows public blob access. Data can be accessed without authentication.",
    severity: "critical",
    cwe: "CWE-284",
    provider: "azure",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml"],
    patterns: [
      /allow_blob_public_access\s*=\s*true/gi,
      /publicAccess.*(?:Blob|Container)/gi,
    ],
  },
  {
    id: "azure-nsg-any",
    title: "Azure: NSG with Any-to-Any Rule",
    description: "Network Security Group allows all traffic. This defeats network segmentation.",
    severity: "high",
    cwe: "CWE-284",
    provider: "azure",
    filePatterns: ["**/*.tf", "**/*.json"],
    patterns: [
      /source_address_prefix\s*=\s*["']\*["']/gi,
      /destination_port_range\s*=\s*["']\*["']/gi,
    ],
  },
  {
    id: "azure-app-no-https",
    title: "Azure: App Service Without HTTPS Only",
    description: "Azure App Service allows HTTP connections. Force HTTPS to protect data in transit.",
    severity: "medium",
    cwe: "CWE-319",
    provider: "azure",
    filePatterns: ["**/*.tf", "**/*.json"],
    patterns: [
      /https_only\s*=\s*false/gi,
    ],
  },

  // === GCP ===
  {
    id: "gcp-bucket-public",
    title: "GCP: Cloud Storage Bucket with allUsers Access",
    description: "GCP storage bucket grants access to allUsers or allAuthenticatedUsers. Data is publicly accessible.",
    severity: "critical",
    cwe: "CWE-284",
    provider: "gcp",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml"],
    patterns: [
      /member\s*[:=]\s*["']allUsers["']/gi,
      /member\s*[:=]\s*["']allAuthenticatedUsers["']/gi,
      /members.*allUsers/gi,
    ],
  },
  {
    id: "gcp-firewall-open",
    title: "GCP: Firewall Rule Allows All Sources",
    description: "GCP firewall rule allows traffic from 0.0.0.0/0. Restrict to specific IP ranges.",
    severity: "high",
    cwe: "CWE-284",
    provider: "gcp",
    filePatterns: ["**/*.tf", "**/*.json"],
    patterns: [
      /source_ranges\s*[:=]\s*\[\s*["']0\.0\.0\.0\/0["']/gi,
    ],
  },
  {
    id: "gcp-sql-no-ssl",
    title: "GCP: Cloud SQL Without SSL Enforcement",
    description: "Cloud SQL instance does not require SSL connections. Data transmitted in cleartext.",
    severity: "high",
    cwe: "CWE-319",
    provider: "gcp",
    filePatterns: ["**/*.tf"],
    patterns: [
      /require_ssl\s*=\s*false/gi,
    ],
  },

  // === General Cloud ===
  {
    id: "cloud-secrets-in-config",
    title: "Cloud: Secrets in Infrastructure Config",
    description: "Credentials or secrets hardcoded in cloud configuration files. Use a secrets manager.",
    severity: "critical",
    cwe: "CWE-798",
    provider: "general",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml", "**/*.yaml"],
    patterns: [
      /(?:password|secret_key|access_key|api_key|private_key)\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    ],
  },
  {
    id: "cloud-no-encryption",
    title: "Cloud: Storage Without Encryption at Rest",
    description: "Cloud storage resource without server-side encryption enabled.",
    severity: "high",
    cwe: "CWE-311",
    provider: "general",
    filePatterns: ["**/*.tf", "**/*.json"],
    patterns: [
      /encrypted\s*[:=]\s*false/gi,
      /server_side_encryption\s*[:=]\s*["'](?:none|disabled)["']/gi,
    ],
  },
  {
    id: "cloud-overprivileged",
    title: "Cloud: Overprivileged Service Role",
    description: "Service or function role has admin/full-access permissions. Follow the principle of least privilege.",
    severity: "high",
    cwe: "CWE-250",
    provider: "general",
    filePatterns: ["**/*.tf", "**/*.json", "**/*.yml"],
    patterns: [
      /(?:Admin|FullAccess|PowerUser)(?:Access|Policy)/gi,
      /AdministratorAccess/gi,
      /role.*(?:admin|superuser|root)/gi,
    ],
  },
];

export interface CloudScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class CloudSecurityScanner {
  async scan(projectPath: string): Promise<CloudScanResult> {
    const allPatterns = [...new Set(CLOUD_RULES.flatMap((r) => r.filePatterns))];

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
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }

      // Quick check: skip files without cloud references
      if (!/aws|azure|gcp|google|terraform|cloudformation|pulumi|s3|iam|lambda|ec2|rds|storage|firewall/i.test(content)) {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of CLOUD_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            if (pattern.test(lines[i])) {
              findings.push({
                id: `CLOUD-${String(idCounter++).padStart(4, "0")}`,
                rule: `cloud:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "cloud",
                cwe: rule.cwe,
                confidence: "high",
                location: {
                  file: relativePath,
                  line: i + 1,
                  snippet: lines[i].trim(),
                },
              });
            }
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
