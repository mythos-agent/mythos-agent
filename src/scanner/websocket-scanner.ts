import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface WsRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}

const WS_RULES: WsRule[] = [
  {
    id: "ws-no-auth",
    title: "WebSocket: No Authentication on Connection",
    description: "WebSocket connection established without verifying user identity. Authenticate via token in handshake or first message.",
    severity: "high",
    cwe: "CWE-306",
    patterns: [
      /(?:wss|WebSocketServer|Server)\s*\(\s*\{(?![\s\S]{0,300}(?:verifyClient|auth|token|jwt|session))/gi,
      /\.on\s*\(\s*['"]connection['"].*(?:ws|socket|client)\s*(?:,\s*req)?\s*(?:=>|\))\s*\{(?![\s\S]{0,200}(?:auth|token|verify|session))/gi,
    ],
  },
  {
    id: "ws-no-origin-check",
    title: "WebSocket: No Origin Validation",
    description: "WebSocket server does not validate the Origin header. Any website can connect, enabling CSWSH (Cross-Site WebSocket Hijacking).",
    severity: "high",
    cwe: "CWE-346",
    patterns: [
      /(?:WebSocketServer|wss\.Server|Server)\s*\(\s*\{(?![\s\S]{0,300}(?:verifyClient|origin|allowedOrigins))/gi,
    ],
  },
  {
    id: "ws-no-message-validation",
    title: "WebSocket: No Message Validation",
    description: "WebSocket messages processed without schema validation or type checking. Malformed messages can cause errors or exploits.",
    severity: "medium",
    cwe: "CWE-20",
    patterns: [
      /\.on\s*\(\s*['"]message['"].*JSON\.parse\s*\(\s*(?:data|message|msg)(?![\s\S]{0,200}(?:validate|schema|joi|zod|ajv|yup))/gi,
    ],
  },
  {
    id: "ws-no-size-limit",
    title: "WebSocket: No Message Size Limit",
    description: "No maximum message size configured. Attackers can send huge messages to exhaust server memory.",
    severity: "medium",
    cwe: "CWE-770",
    patterns: [
      /new\s+(?:WebSocketServer|Server)\s*\(\s*\{(?![\s\S]{0,200}(?:maxPayload|maxReceivedFrameSize|maxMessageSize))/gi,
    ],
  },
  {
    id: "ws-no-rate-limit",
    title: "WebSocket: No Message Rate Limiting",
    description: "No rate limiting on WebSocket messages. Clients can flood the server with messages.",
    severity: "medium",
    cwe: "CWE-799",
    patterns: [
      /\.on\s*\(\s*['"]message['"](?![\s\S]{0,300}(?:rateLimit|throttle|rateLimiter|messageCount|lastMessage))/gi,
    ],
  },
  {
    id: "ws-broadcast-unfiltered",
    title: "WebSocket: Broadcasting Unfiltered User Input",
    description: "User message broadcast to all clients without sanitization. Can enable XSS or injection in other clients.",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /(?:broadcast|clients\.forEach|wss\.clients)[\s\S]{0,100}(?:send|write)\s*\(\s*(?:data|message|msg)(?![\s\S]{0,100}(?:sanitize|escape|encode|filter))/gi,
    ],
  },
  {
    id: "ws-eval-message",
    title: "WebSocket: Executing Received Message",
    description: "WebSocket message content passed to eval or Function constructor. Remote code execution via WebSocket.",
    severity: "critical",
    cwe: "CWE-95",
    patterns: [
      /\.on\s*\(\s*['"]message['"][\s\S]{0,200}eval\s*\(/gi,
      /\.on\s*\(\s*['"]message['"][\s\S]{0,200}new\s+Function\s*\(/gi,
    ],
  },
];

export interface WebsocketScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class WebsocketScanner {
  async scan(projectPath: string): Promise<WebsocketScanResult> {
    const files = await glob(
      ["**/*.ts", "**/*.js"],
      {
        cwd: projectPath,
        absolute: true,
        ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**"],
        nodir: true,
      }
    );

    const findings: Vulnerability[] = [];
    let idCounter = 1;

    for (const file of files) {
      let content: string;
      try {
        const stats = fs.statSync(file);
        if (stats.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch { continue; }

      if (!/websocket|socket\.io|ws|wss|WebSocket/i.test(content)) continue;

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of WS_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          const match = pattern.exec(content);
          if (match) {
            const lineNum = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `WS-${String(idCounter++).padStart(4, "0")}`,
              rule: `ws:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "websocket",
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
