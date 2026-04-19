// VULNERABLE fixture for SPX-BENCH-0004.
// Do not import or execute — this file is benchmark input only.
//
// CSP allows both 'unsafe-inline' and 'unsafe-eval', re-enabling the
// XSS vectors CSP is supposed to block. Worse than no CSP because
// compliance checks often treat header presence as sufficient.
//
// The header name and the unsafe value are intentionally on one line
// so the scanner's line-based regex sees both together.

import express from "express";

export const app = express();

app.use((_req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'");
  next();
});

app.get("/", (_req, res) => {
  res.send("<h1>Hello</h1>");
});
