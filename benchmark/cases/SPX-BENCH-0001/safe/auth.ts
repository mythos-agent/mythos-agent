// SPX-BENCH-0001 — SAFE VERSION
//
// Fix: hold the token only in memory for the lifetime of the page.
// The server issues a short-lived access token in-response and a
// long-lived refresh token as an HttpOnly, SameSite=Strict cookie.
// Neither token is readable from arbitrary JavaScript.

let tokenInMemory: string | null = null;

export function storeAuthToken(token: string): void {
  tokenInMemory = token;
}

export function readAuthToken(): string | null {
  return tokenInMemory;
}

export function clearAuthToken(): void {
  tokenInMemory = null;
}
