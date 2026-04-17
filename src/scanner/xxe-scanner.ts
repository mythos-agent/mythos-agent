import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

const XXE_RULES: Array<{
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}> = [
  {
    id: "xxe-dom-parser",
    title: "XXE: DOMParser Without Entity Restriction",
    description:
      "DOMParser or xml2js used without disabling external entities. Enables file read, SSRF, and DoS via XML.",
    severity: "high",
    cwe: "CWE-611",
    patterns: [
      /new\s+DOMParser\s*\(\s*\)/gi,
      /xml2js\.parseString\s*\(/gi,
      /parseXML\s*\(\s*(?:req|input|data|body)/gi,
    ],
  },
  {
    id: "xxe-libxml",
    title: "XXE: libxml/lxml Without Safe Options",
    description:
      "Python lxml or libxml used without resolve_entities=False. External entities enable arbitrary file read.",
    severity: "high",
    cwe: "CWE-611",
    patterns: [
      /etree\.(?:parse|fromstring|XML)\s*\((?![\s\S]{0,100}resolve_entities\s*=\s*False)/gi,
      /etree\.XMLParser\s*\((?![\s\S]{0,100}resolve_entities\s*=\s*False)/gi,
    ],
  },
  {
    id: "xxe-java-sax",
    title: "XXE: Java SAX/DOM Parser Without Feature Restrictions",
    description:
      "Java XML parser without disabling DOCTYPE and external entities. Set disallow-doctype-decl feature.",
    severity: "high",
    cwe: "CWE-611",
    patterns: [
      /(?:SAXParserFactory|DocumentBuilderFactory|XMLInputFactory)\.new(?:Instance|Factory)\s*\((?![\s\S]{0,300}(?:disallow-doctype|external-general-entities.*false))/gi,
    ],
  },
  {
    id: "xxe-xslt",
    title: "XXE: XSLT Processing with User Input",
    description:
      "XSLT transformation with user-supplied stylesheet. XSLT can execute arbitrary code and read files.",
    severity: "critical",
    cwe: "CWE-611",
    patterns: [/(?:xsltProcessor|transform|XSLTProcessor).*(?:req\.|input|user|data)/gi],
  },
  {
    id: "xxe-svg",
    title: "XXE: SVG Upload Without Sanitization",
    description:
      "SVG files can contain XML entities and JavaScript. Sanitize SVG uploads or convert to raster format.",
    severity: "medium",
    cwe: "CWE-611",
    patterns: [/(?:upload|multer|formidable)[\s\S]{0,200}(?:svg|image\/svg)/gi],
  },
];

export interface XxeScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class XxeScanner {
  async scan(projectPath: string): Promise<XxeScanResult> {
    const files = await glob(["**/*.ts", "**/*.js", "**/*.py", "**/*.java"], {
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
      if (!/xml|parse|dom|sax|etree|xslt|svg/i.test(content)) continue;
      const lines = content.split("\n");
      const rel = path.relative(projectPath, file);
      for (const rule of XXE_RULES) {
        for (const p of rule.patterns) {
          p.lastIndex = 0;
          const match = p.exec(content);
          if (match) {
            const ln = content.slice(0, match.index).split("\n").length;
            findings.push({
              id: `XXE-${String(id++).padStart(4, "0")}`,
              rule: `xxe:${rule.id}`,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              category: "xxe",
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
