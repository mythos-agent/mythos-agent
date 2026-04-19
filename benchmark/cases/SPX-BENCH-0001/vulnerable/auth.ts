// SPX-BENCH-0001 — VULNERABLE FIXTURE
//
// Vulnerability: JWT persisted to browser localStorage.
// Anything that can run JavaScript in the user's tab (XSS, compromised
// third-party script, browser extension with host permission) can read
// this value. localStorage has no HttpOnly protection.

export function storeAuthToken(token: string): void {
  localStorage.setItem("jwt", token);
}

export function readAuthToken(): string | null {
  return localStorage.getItem("jwt");
}
