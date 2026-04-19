// SAFE fixture for SPX-BENCH-0004 — the intended fix shape.
//
// Strict CSP with no 'unsafe-inline' or 'unsafe-eval'. A production
// system that needs inline scripts or styles would attach a per-
// response nonce to script-src/style-src (e.g., 'nonce-abc123') and
// emit that same nonce on the allowed inline elements.
//
// Header name and value kept on the same line to mirror the
// vulnerable fixture's shape (makes the diff between the two cases
// purely about the value, not structure).

import express from "express";

export const app = express();

app.use((_req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'");
  next();
});

app.get("/", (_req, res) => {
  res.send("<h1>Hello</h1>");
});
