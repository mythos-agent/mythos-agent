import type { Vulnerability, Severity } from "../types/index.js";
import type { Endpoint } from "../analysis/endpoint-mapper.js";
import { getPayloads, generateTargetedPayloads, type TestPayload } from "./payload-generator.js";

export interface FuzzResult {
  endpoint: string;
  method: string;
  payload: TestPayload;
  statusCode: number;
  responseTime: number;
  responseBody: string;
  vulnerable: boolean;
  evidence?: string;
}

export interface FuzzReport {
  target: string;
  endpointsTested: number;
  payloadsSent: number;
  vulnerabilitiesFound: number;
  results: FuzzResult[];
  findings: Vulnerability[];
  duration: number;
}

/**
 * Run fuzzing against discovered endpoints.
 * Sends security payloads and analyzes responses for vulnerability indicators.
 */
export async function fuzzEndpoints(
  baseUrl: string,
  endpoints: Endpoint[],
  options: {
    categories?: string[];
    timeout?: number;
    maxPayloadsPerEndpoint?: number;
    targetedOnly?: boolean;
  } = {}
): Promise<FuzzReport> {
  const { timeout = 10000, maxPayloadsPerEndpoint = 10, targetedOnly = false } = options;

  const start = Date.now();
  const results: FuzzResult[] = [];
  let payloadsSent = 0;

  for (const endpoint of endpoints) {
    const url = `${baseUrl}${endpoint.path}`;
    const payloads = targetedOnly
      ? generateTargetedPayloads(endpoint.riskReason?.split(" ")[0] || "")
      : getPayloads();

    for (const payload of payloads.slice(0, maxPayloadsPerEndpoint)) {
      payloadsSent++;
      const result = await sendPayload(url, endpoint.method, payload, timeout);
      results.push(result);
    }
  }

  const vulnerableResults = results.filter((r) => r.vulnerable);
  const findings = vulnerableResults.map((r, i) => resultToVulnerability(r, i));

  return {
    target: baseUrl,
    endpointsTested: endpoints.length,
    payloadsSent,
    vulnerabilitiesFound: vulnerableResults.length,
    results: vulnerableResults,
    findings,
    duration: Date.now() - start,
  };
}

async function sendPayload(
  url: string,
  method: string,
  payload: TestPayload,
  timeout: number
): Promise<FuzzResult> {
  const startTime = Date.now();

  // Inject payload into query params for GET, body for POST
  const targetUrl =
    method === "GET"
      ? `${url}?input=${encodeURIComponent(payload.value)}&q=${encodeURIComponent(payload.value)}`
      : url;

  const body = ["POST", "PUT", "PATCH"].includes(method)
    ? JSON.stringify({ input: payload.value, data: payload.value, q: payload.value })
    : undefined;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(targetUrl, {
      method,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "shedu/1.0 (security-scanner)",
      },
      body,
      signal: controller.signal,
      redirect: "manual",
    });

    clearTimeout(timer);

    const responseBody = await response.text().catch(() => "");
    const responseTime = Date.now() - startTime;

    // Check for vulnerability indicators
    const vulnerable = checkVulnerable(
      payload,
      response.status,
      responseBody,
      responseTime,
      response.headers
    );

    return {
      endpoint: url,
      method,
      payload,
      statusCode: response.status,
      responseTime,
      responseBody: responseBody.slice(0, 1000),
      vulnerable: vulnerable.isVuln,
      evidence: vulnerable.evidence,
    };
  } catch (err) {
    return {
      endpoint: url,
      method,
      payload,
      statusCode: 0,
      responseTime: Date.now() - startTime,
      responseBody: "",
      vulnerable: false,
    };
  }
}

function checkVulnerable(
  payload: TestPayload,
  statusCode: number,
  body: string,
  responseTime: number,
  headers: Headers
): { isVuln: boolean; evidence?: string } {
  // Check if payload pattern is reflected in response (detect pattern)
  if (payload.detectPattern.test(body)) {
    return {
      isVuln: true,
      evidence: `Response contains vulnerability indicator matching '${payload.detectPattern.source}'`,
    };
  }

  // Time-based detection (for blind injections)
  if (payload.name.includes("Time-based") && responseTime > 4500) {
    return {
      isVuln: true,
      evidence: `Response delayed ${responseTime}ms (expected ~5000ms for time-based injection)`,
    };
  }

  // Redirect detection
  if (payload.category === "redirect" && [301, 302, 303, 307, 308].includes(statusCode)) {
    const location = headers.get("location") || "";
    if (location.includes("evil.com") || location.startsWith("//")) {
      return {
        isVuln: true,
        evidence: `Redirect to external URL: ${location}`,
      };
    }
  }

  // Error-based SQL injection
  if (payload.category === "sqli" && statusCode === 500) {
    if (/sql|syntax|query|database|ORA-|PG::/i.test(body)) {
      return {
        isVuln: true,
        evidence: `Server error with database error message exposed`,
      };
    }
  }

  return { isVuln: false };
}

function resultToVulnerability(result: FuzzResult, index: number): Vulnerability {
  return {
    id: `FUZZ-${String(index + 1).padStart(4, "0")}`,
    rule: `dast:${result.payload.category}`,
    title: `DAST: ${result.payload.name} — ${result.endpoint}`,
    description: `Dynamic test confirmed vulnerability. Payload: "${result.payload.value.slice(0, 50)}". ${result.evidence || ""}`,
    severity: result.payload.severity,
    category: "dast",
    cwe: result.payload.cwe,
    confidence: "high",
    location: {
      file: result.endpoint,
      line: 0,
      snippet: `${result.method} ${result.endpoint} — Status: ${result.statusCode}, Time: ${result.responseTime}ms`,
    },
  };
}
