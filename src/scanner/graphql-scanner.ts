import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface GqlRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}

const GQL_RULES: GqlRule[] = [
  {
    id: "gql-introspection-enabled",
    title: "GraphQL: Introspection Enabled in Production",
    description:
      "GraphQL introspection exposes your entire API schema. Disable it in production to prevent reconnaissance.",
    severity: "medium",
    cwe: "CWE-200",
    patterns: [
      /introspection\s*:\s*true/gi,
      /graphqlHTTP\s*\(\s*\{(?![\s\S]{0,200}introspection\s*:\s*false)/gi,
    ],
  },
  {
    id: "gql-no-depth-limit",
    title: "GraphQL: No Query Depth Limiting",
    description:
      "No query depth limit configured. Attackers can craft deeply nested queries to cause DoS.",
    severity: "high",
    cwe: "CWE-770",
    patterns: [
      /(?:ApolloServer|createServer|graphqlHTTP)\s*\(\s*\{(?![\s\S]{0,300}(?:depthLimit|maxDepth|queryDepth|validationRules))/gi,
    ],
  },
  {
    id: "gql-no-cost-analysis",
    title: "GraphQL: No Query Cost/Complexity Analysis",
    description:
      "No query cost limiting. Attackers can request expensive field combinations to exhaust server resources.",
    severity: "medium",
    cwe: "CWE-770",
    patterns: [
      /(?:ApolloServer|createServer)\s*\(\s*\{(?![\s\S]{0,300}(?:costAnalysis|complexityLimit|queryComplexity))/gi,
    ],
  },
  {
    id: "gql-no-rate-limit",
    title: "GraphQL: No Rate Limiting on Endpoint",
    description:
      "GraphQL endpoint without rate limiting. Single endpoint handles all queries, making DoS easier.",
    severity: "medium",
    cwe: "CWE-307",
    patterns: [
      /app\.use\s*\(\s*['"]\/graphql['"](?![\s\S]{0,200}(?:rateLimit|throttle|rateLimiter))/gi,
    ],
  },
  {
    id: "gql-batching-enabled",
    title: "GraphQL: Query Batching Enabled Without Limits",
    description:
      "Query batching allows sending multiple operations in one request. Without limits, this amplifies other attacks.",
    severity: "low",
    cwe: "CWE-770",
    patterns: [/allowBatchedHttpRequests\s*:\s*true/gi, /batching\s*:\s*true/gi],
  },
  {
    id: "gql-no-field-auth",
    title: "GraphQL: Resolver Without Authorization Check",
    description:
      "GraphQL resolver accesses data without checking user permissions. Each resolver should verify authorization.",
    severity: "high",
    cwe: "CWE-285",
    patterns: [
      /(?:Query|Mutation)\s*[:=]\s*\{[\s\S]*?(?:resolve|handler)\s*[:=]\s*(?:async\s+)?\([^)]*\)\s*(?:=>|{)(?![\s\S]{0,100}(?:auth|permission|role|isAdmin|context\.user|req\.user))/gi,
    ],
  },
  {
    id: "gql-debug-mode",
    title: "GraphQL: Debug Mode / Stack Trace Exposure",
    description:
      "GraphQL server configured with debug or detailed error messages. This leaks internal information.",
    severity: "medium",
    cwe: "CWE-209",
    patterns: [
      /debug\s*:\s*true.*(?:graphql|apollo)/gi,
      /formatError.*stack/gi,
      /includeStacktraceInErrorResponses\s*:\s*true/gi,
    ],
  },
  {
    id: "gql-sql-in-resolver",
    title: "GraphQL: SQL Query in Resolver with User Input",
    description:
      "Raw SQL query in GraphQL resolver using arguments directly. Use parameterized queries.",
    severity: "critical",
    cwe: "CWE-89",
    patterns: [/resolve.*args[\s\S]{0,100}(?:query|execute|raw)\s*\(.*(?:args\.|input\.)/gi],
  },
];

export interface GraphqlScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class GraphqlScanner {
  async scan(projectPath: string): Promise<GraphqlScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py"], {
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

      if (!/graphql|apollo|gql|schema|resolver|typeDefs|Query|Mutation/i.test(content)) continue;

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of GQL_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          const match = pattern.exec(content);
          if (match) {
            const lineNum = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `GQL-${String(idCounter++).padStart(4, "0")}`,
              rule: `graphql:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "graphql",
              cwe: rule.cwe,
              confidence: "medium",
              location: {
                file: relativePath,
                line: lineNum,
                snippet: lines[lineNum - 1]?.trim() || "",
              },
            });
            break;
          }
        }
      }
    }

    return { findings, filesScanned: files.length };
  }
}
