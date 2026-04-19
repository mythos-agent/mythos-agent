// VULNERABLE fixture for SPX-BENCH-0003.
// Do not import or execute — this file is benchmark input only.
//
// The session cookie is missing both httpOnly and secure. XSS on the
// origin reads document.cookie and exfiltrates the session id; an
// http:// request ever sends the cookie in cleartext.

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
    },
  })
);

app.get("/", (_req, res) => {
  res.send("ok");
});
