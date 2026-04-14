import type { CodebaseMap, RouteDef } from "./code-parser.js";

export interface Endpoint {
  method: string;
  path: string;
  file: string;
  line: number;
  hasAuth: boolean;
  authType?: string;
  middleware: string[];
  riskLevel: "high" | "medium" | "low";
  riskReason?: string;
}

const AUTH_MIDDLEWARE_PATTERNS = [
  "auth", "authenticate", "authorize", "requireAuth", "ensureAuth",
  "verifyToken", "checkToken", "requireLogin", "isAuthenticated",
  "passport", "jwt", "session", "apiKey", "bearer",
  "login_required", "permission_required", "IsAuthenticated",
];

const SENSITIVE_PATH_PATTERNS = [
  /admin/i, /user/i, /account/i, /payment/i, /billing/i,
  /password/i, /token/i, /secret/i, /api\/v\d/i, /internal/i,
  /delete/i, /export/i, /import/i, /upload/i, /download/i,
  /config/i, /setting/i, /role/i, /permission/i,
];

/**
 * Map all API endpoints and assess their security posture.
 */
export function mapEndpoints(codebaseMap: CodebaseMap): Endpoint[] {
  return codebaseMap.routes.map((route) => {
    const hasAuth = checkHasAuth(route);
    const riskAssessment = assessRisk(route, hasAuth);

    return {
      method: route.method,
      path: route.path,
      file: route.file,
      line: route.line,
      hasAuth,
      authType: hasAuth ? detectAuthType(route) : undefined,
      middleware: route.middleware,
      riskLevel: riskAssessment.level,
      riskReason: riskAssessment.reason,
    };
  });
}

/**
 * Find endpoints that are potentially unprotected.
 */
export function findUnprotectedEndpoints(endpoints: Endpoint[]): Endpoint[] {
  return endpoints.filter((ep) => {
    if (ep.hasAuth) return false;
    // Public paths are OK
    if (isLikelyPublic(ep.path, ep.method)) return false;
    // Sensitive paths without auth are a problem
    return SENSITIVE_PATH_PATTERNS.some((p) => p.test(ep.path));
  });
}

/**
 * Generate a security assessment of the endpoint map.
 */
export function assessEndpointSecurity(endpoints: Endpoint[]): {
  total: number;
  authenticated: number;
  unauthenticated: number;
  highRisk: Endpoint[];
  summary: string;
} {
  const authenticated = endpoints.filter((e) => e.hasAuth).length;
  const unauthenticated = endpoints.filter((e) => !e.hasAuth).length;
  const highRisk = endpoints.filter((e) => e.riskLevel === "high");

  const authPct = endpoints.length > 0
    ? Math.round((authenticated / endpoints.length) * 100)
    : 100;

  let summary: string;
  if (highRisk.length > 0) {
    summary = `${highRisk.length} high-risk endpoints found. ${authPct}% of endpoints have authentication.`;
  } else if (unauthenticated > 0) {
    summary = `${unauthenticated} unauthenticated endpoints. ${authPct}% coverage.`;
  } else {
    summary = `All ${endpoints.length} endpoints have authentication. Good coverage.`;
  }

  return { total: endpoints.length, authenticated, unauthenticated, highRisk, summary };
}

function checkHasAuth(route: RouteDef): boolean {
  // Check if any middleware looks like auth
  return route.middleware.some((m) =>
    AUTH_MIDDLEWARE_PATTERNS.some((pattern) =>
      m.toLowerCase().includes(pattern.toLowerCase())
    )
  );
}

function detectAuthType(route: RouteDef): string {
  const allMiddleware = route.middleware.join(" ").toLowerCase();
  if (allMiddleware.includes("jwt") || allMiddleware.includes("bearer")) return "JWT";
  if (allMiddleware.includes("session")) return "Session";
  if (allMiddleware.includes("apikey") || allMiddleware.includes("api_key")) return "API Key";
  if (allMiddleware.includes("passport")) return "Passport";
  if (allMiddleware.includes("oauth")) return "OAuth";
  return "Unknown";
}

function assessRisk(
  route: RouteDef,
  hasAuth: boolean
): { level: "high" | "medium" | "low"; reason?: string } {
  // Write operations without auth are high risk
  if (!hasAuth && ["POST", "PUT", "PATCH", "DELETE"].includes(route.method)) {
    return {
      level: "high",
      reason: `${route.method} endpoint without authentication`,
    };
  }

  // Sensitive paths without auth
  if (!hasAuth && SENSITIVE_PATH_PATTERNS.some((p) => p.test(route.path))) {
    return {
      level: "high",
      reason: `Sensitive path '${route.path}' without authentication`,
    };
  }

  // Admin/internal paths
  if (route.path.toLowerCase().includes("admin") || route.path.toLowerCase().includes("internal")) {
    return hasAuth
      ? { level: "medium", reason: "Admin endpoint — verify authorization checks" }
      : { level: "high", reason: "Admin endpoint without authentication" };
  }

  if (!hasAuth) return { level: "medium" };
  return { level: "low" };
}

function isLikelyPublic(routePath: string, method: string): boolean {
  const publicPaths = [
    "/health", "/healthz", "/ready", "/readyz",
    "/ping", "/status", "/version",
    "/login", "/signup", "/register", "/auth",
    "/public", "/static", "/assets",
    "/docs", "/swagger", "/openapi",
    "/favicon", "/robots.txt", "/sitemap",
    "/", "/index",
  ];

  return publicPaths.some((p) =>
    routePath.toLowerCase() === p || routePath.toLowerCase().startsWith(p + "/")
  );
}
