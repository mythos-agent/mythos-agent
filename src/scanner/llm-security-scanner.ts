import fs from "node:fs";
import path from "node:path";
import { glob } from "glob";
import type { Vulnerability, Severity } from "../types/index.js";

interface LlmRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  patterns: RegExp[];
}

const LLM_RULES: LlmRule[] = [
  // Prompt Injection
  {
    id: "llm-prompt-injection",
    title: "LLM Prompt Injection: User input in prompt",
    description:
      "User-controlled input is concatenated into an LLM prompt without sanitization. An attacker can manipulate the AI's behavior via crafted input.",
    severity: "critical",
    cwe: "CWE-77",
    patterns: [
      /(?:messages|prompt)\s*[=:]\s*[`"'].*\$\{.*(?:req|input|user|body|query|params)/gi,
      /(?:content|role).*\+\s*(?:req\.|input|user|body|query|params)/gi,
      /f".*\{(?:user_input|request|query|message).*(?:system|assistant|user)/gi,
      /\.format\(.*(?:user_input|request|query).*(?:prompt|message)/gi,
    ],
  },

  // Unsafe eval of AI output
  {
    id: "llm-unsafe-eval",
    title: "LLM Output Execution: eval/exec on AI response",
    description:
      "LLM output is passed to eval() or exec(). An attacker who controls the prompt can achieve arbitrary code execution.",
    severity: "critical",
    cwe: "CWE-95",
    patterns: [
      /eval\s*\(\s*(?:response|result|output|completion|message|content|text)(?:\.\w+)*\s*\)/gi,
      /exec\s*\(\s*(?:response|result|output|completion|message|content|text)/gi,
      /new\s+Function\s*\(\s*(?:response|result|output|completion)/gi,
      /subprocess\.run\s*\(.*(?:response|result|output|completion)/gi,
    ],
  },

  // Client-side API key exposure
  {
    id: "llm-client-api-key",
    title: "LLM API Key in Client Code",
    description:
      "LLM API key is used in client-side code. This exposes the key to all users and enables API abuse.",
    severity: "critical",
    cwe: "CWE-798",
    patterns: [
      /(?:NEXT_PUBLIC|REACT_APP|VITE|NUXT_PUBLIC)_.*(?:OPENAI|ANTHROPIC|API).*KEY/gi,
      /(?:openai|anthropic).*apiKey\s*[:=]\s*["'][^"']+["']/gi,
      /fetch\s*\(\s*["']https:\/\/api\.openai\.com.*["'].*(?:Authorization|x-api-key|api-key)/gi,
    ],
  },

  // XSS via AI output
  {
    id: "llm-xss-output",
    title: "XSS via LLM: AI response rendered without escaping",
    description:
      "LLM output is rendered as HTML without sanitization. If the AI is manipulated to output script tags, XSS occurs.",
    severity: "high",
    cwe: "CWE-79",
    patterns: [
      /dangerouslySetInnerHTML.*(?:response|result|output|completion|message|content|aiResponse|chatResponse)/gi,
      /\.innerHTML\s*=\s*(?:response|result|output|completion|message|content)/gi,
      /v-html\s*=\s*["'](?:response|result|output|message)/gi,
    ],
  },

  // Cost attack — no token limits
  {
    id: "llm-no-token-limit",
    title: "LLM Cost Attack: No max_tokens limit",
    description:
      "API call to LLM without max_tokens/maxTokens. An attacker could craft inputs that generate extremely long (expensive) responses.",
    severity: "medium",
    cwe: "CWE-770",
    patterns: [
      /(?:openai|anthropic|client)\.\w*\.create\s*\(\s*\{(?:(?!max_tokens|maxTokens|max_output_tokens)[\s\S])*\}\s*\)/gi,
    ],
  },

  // System prompt leakage
  {
    id: "llm-system-prompt-leak",
    title: "LLM System Prompt Leakage Risk",
    description:
      "System prompt is stored in a client-accessible constant or sent to the frontend. Attackers can extract it to reverse-engineer the application.",
    severity: "medium",
    cwe: "CWE-200",
    patterns: [
      /(?:export|const|let|var)\s+(?:SYSTEM_PROMPT|systemPrompt|system_prompt|SYSTEM_MESSAGE)\s*=\s*[`"']/gi,
      /(?:system|systemMessage|system_prompt)\s*[:=]\s*[`"'](?:You are|Act as|Your role)/gi,
    ],
  },

  // PII to external LLM
  {
    id: "llm-pii-exposure",
    title: "PII Sent to External LLM API",
    description:
      "Personal or sensitive data may be sent to an external LLM API without filtering. This may violate privacy regulations.",
    severity: "high",
    cwe: "CWE-359",
    patterns: [
      /(?:messages|prompt|content).*(?:email|password|ssn|social_security|credit_card|phone_number|address).*(?:openai|anthropic|api)/gi,
      /(?:openai|anthropic).*(?:email|password|ssn|creditCard|phoneNumber)/gi,
    ],
  },

  // Insecure AI tool use
  {
    id: "llm-insecure-tool-use",
    title: "LLM Insecure Tool Use: AI can execute system commands",
    description:
      "The LLM is given tools/functions that execute shell commands or file operations. A compromised prompt could lead to system compromise.",
    severity: "critical",
    cwe: "CWE-78",
    patterns: [
      /(?:tools|functions)\s*[:=].*(?:exec|spawn|execSync|child_process|os\.system|subprocess)/gi,
      /function_call.*(?:exec|shell|command|run_command|execute)/gi,
      /tool.*(?:name|function).*(?:execute_code|run_shell|file_write|delete_file)/gi,
    ],
  },

  // AI response in SQL/command
  {
    id: "llm-response-injection",
    title: "LLM Response Used in SQL/Command Without Sanitization",
    description:
      "LLM output is used in a SQL query or shell command. If the AI output is manipulated, this leads to injection.",
    severity: "critical",
    cwe: "CWE-89",
    patterns: [
      /(?:query|execute|exec)\s*\(.*(?:response|result|output|completion|aiResponse|chatResponse)/gi,
      /(?:spawn|execSync|exec)\s*\(.*(?:response|result|output|completion)/gi,
    ],
  },

  // Missing content filtering
  {
    id: "llm-no-content-filter",
    title: "LLM: No Content Filtering on Output",
    description:
      "LLM output is used without content moderation or filtering. AI may generate harmful, biased, or inappropriate content.",
    severity: "medium",
    cwe: "CWE-20",
    patterns: [/(?:response|completion|result)\.(?:content|text|message)\s*(?:\.trim\(\))?$/gm],
  },

  // Hardcoded model endpoints
  {
    id: "llm-hardcoded-endpoint",
    title: "LLM: Hardcoded API Endpoint",
    description:
      "LLM API endpoint is hardcoded. Use configuration or environment variables for flexibility and to avoid leaking internal endpoints.",
    severity: "low",
    cwe: "CWE-547",
    patterns: [
      /["']https:\/\/api\.openai\.com\/v1\/(?:chat\/completions|completions|embeddings)["']/gi,
      /["']https:\/\/api\.anthropic\.com\/v1\/messages["']/gi,
    ],
  },

  // Model version exposure
  {
    id: "llm-model-exposure",
    title: "LLM Model Info Exposed to Users",
    description:
      "The specific model name/version is sent to the client. This leaks implementation details attackers can use.",
    severity: "low",
    cwe: "CWE-200",
    patterns: [/res\.(?:json|send)\s*\(.*(?:model|modelName|model_version)/gi],
  },

  // Training on user data
  {
    id: "llm-training-data-risk",
    title: "LLM: User Data Used for Fine-Tuning",
    description:
      "User data appears to be collected for model training/fine-tuning. Ensure user consent and data handling compliance.",
    severity: "high",
    cwe: "CWE-359",
    patterns: [
      /(?:fine.?tun|train|finetune).*(?:user_data|userData|customer|input_data)/gi,
      /(?:upload|create).*(?:training.?file|fine.?tun).*(?:user|customer|input)/gi,
    ],
  },
];

export interface LlmScanResult {
  findings: Vulnerability[];
  filesScanned: number;
}

export class LlmSecurityScanner {
  async scan(projectPath: string): Promise<LlmScanResult> {
    const files = await glob(["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.py"], {
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

      // Quick check: skip files that don't reference LLM/AI
      if (
        !/openai|anthropic|llm|gpt|claude|completion|chat.*api|langchain|llamaindex/i.test(content)
      ) {
        continue;
      }

      const lines = content.split("\n");
      const relativePath = path.relative(projectPath, file);

      for (const rule of LLM_RULES) {
        for (const pattern of rule.patterns) {
          pattern.lastIndex = 0;
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            if (pattern.test(lines[i])) {
              findings.push({
                id: `LLM-${String(idCounter++).padStart(4, "0")}`,
                rule: `llm:${rule.id}`,
                title: rule.title,
                description: rule.description,
                severity: rule.severity,
                category: "llm-security",
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
