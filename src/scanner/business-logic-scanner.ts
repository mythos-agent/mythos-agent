import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const BIZ_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "biz-negative-amount",
    title: "Business Logic: No Negative Amount Validation",
    description:
      "Payment/transfer amount used without checking for negative values. Negative amounts can reverse transactions.",
    severity: "high",
    cwe: "CWE-20",
    patterns: [
      /(?:amount|price|total|quantity|balance)\s*[:=]\s*(?:req\.|input|body|parseFloat|parseInt|Number)(?![\s\S]{0,100}(?:<=?\s*0|>=?\s*0|Math\.abs|positive|negative|min\s*\(|validate))/gi,
    ],
  },
  {
    id: "biz-coupon-no-limit",
    title: "Business Logic: Coupon/Discount Without Usage Limit",
    description:
      "Discount or coupon code applied without checking usage count. Same code can be used unlimited times.",
    severity: "medium",
    cwe: "CWE-799",
    patterns: [
      /(?:coupon|discount|promo|voucher)(?![\s\S]{0,200}(?:usageCount|maxUses|limit|used|redeemed|expired))/gi,
    ],
  },
  {
    id: "biz-race-purchase",
    title: "Business Logic: Purchase Without Inventory Lock",
    description:
      "Item purchased without locking inventory. Concurrent purchases can oversell stock.",
    severity: "high",
    cwe: "CWE-362",
    patterns: [
      /(?:purchase|buy|order|checkout)[\s\S]{0,300}(?:stock|inventory|quantity)(?![\s\S]{0,100}(?:lock|transaction|atomic|decrement))/gi,
    ],
  },
  {
    id: "biz-role-escalation",
    title: "Business Logic: User Can Set Own Role",
    description:
      "API allows users to set their own role/permissions. Role changes must be admin-only operations.",
    severity: "critical",
    cwe: "CWE-269",
    patterns: [
      /\.update\s*\(\s*\{.*(?:role|isAdmin|permission|privilege).*req\.body/gi,
      /req\.body\.(?:role|isAdmin|permission|privilege)/gi,
    ],
  },
  {
    id: "biz-email-verify-skip",
    title: "Business Logic: Email Verification Bypassable",
    description:
      "Account actions available without checking email verification status. Users can act on unverified accounts.",
    severity: "medium",
    cwe: "CWE-863",
    patterns: [
      /(?:createOrder|makePayment|postComment|sendMessage)(?![\s\S]{0,200}(?:emailVerified|isVerified|verified))/gi,
    ],
  },
  {
    id: "biz-rate-limit-bypass",
    title: "Business Logic: Rate Limit Based on IP Only",
    description:
      "Rate limiting only checks IP address. Attackers behind proxies or VPNs bypass this. Also rate-limit by user ID.",
    severity: "medium",
    cwe: "CWE-799",
    patterns: [
      /rateLimit\s*\(\s*\{[\s\S]{0,200}(?:keyGenerator|key).*(?:req\.ip|ip|remoteAddress)(?![\s\S]{0,100}(?:userId|user\.id|apiKey))/gi,
    ],
  },
];

export interface BusinessLogicScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class BusinessLogicScanner {
  async scan(projectPath: string): Promise<BusinessLogicScanResult> {
    const files = await glob(["**/*.ts", "**/*.js"], {
      cwd: projectPath,
      absolute: true,
      ignore: ["node_modules/**", "dist/**", ".git/**", ".sphinx/**", "**/*.test.*"],
      nodir: true,
    });
    const findings: Vulnerability[] = [];
    let id = 1;
    for (const file of files) {
      let content: string;
      try {
        const s = fs.statSync(file);
        if (s.size > 500_000) continue;
        content = fs.readFileSync(file, "utf-8");
      } catch {
        continue;
      }
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of BIZ_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `BIZ-${String(id++).padStart(4, "0")}`,
              rule: `biz:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "business-logic",
              cwe: rule.cwe,
              confidence: "medium",
              location: { file: rel, line: ln, snippet: lines[ln - 1]?.trim() || "" },
            });
            break;
          }
        }
      }
    }
    return { findings, filesScanned: files.length };
  }
}
