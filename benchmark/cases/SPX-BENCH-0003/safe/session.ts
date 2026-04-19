// SAFE fixture for SPX-BENCH-0003 — the intended fix shape.
//
// Session cookie sets httpOnly (XSS can't read it), secure (cookie
// only goes over TLS), and sameSite=strict (CSRF defense). Maintains
// a short maxAge so a leaked cookie ages out quickly even if any
// single flag regresses.

import express from "express";
import session from "express-session";

export const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60 * 1000,
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    },
  })
);

app.get("/", (_req, res) => {
  res.send("ok");
});
