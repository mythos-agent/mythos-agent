import express from "express";
import { db } from "./database";

const app = express();
app.use(express.json());

// Vulnerability: SQL Injection — user input concatenated into query
app.get("/api/users/search", (req, res) => {
  const name = req.query.name;
  const result = db.query(`SELECT * FROM users WHERE name = '${name}'`);
  res.json(result);
});

// Vulnerability: Command Injection — user input in exec
app.post("/api/convert", (req, res) => {
  const { exec } = require("child_process");
  const filename = req.body.filename;
  exec(`convert ${filename} output.pdf`, (err: any, stdout: any) => {
    res.json({ status: "ok", output: stdout });
  });
});

// Vulnerability: Path Traversal — user input in file read
app.get("/api/files", (req, res) => {
  const fs = require("fs");
  const path = require("path");
  const filePath = path.join("/uploads", req.query.path as string);
  const content = fs.readFileSync(filePath, "utf-8");
  res.send(content);
});

// Vulnerability: XSS — dangerouslySetInnerHTML usage
app.get("/api/preview", (req, res) => {
  const userContent = req.query.content;
  res.send(`<div dangerouslySetInnerHTML={{ __html: "${userContent}" }} />`);
});

// Vulnerability: Hardcoded secret
const API_SECRET = "sk-ant-api03-FAKE-KEY-DO-NOT-USE-1234567890abcdef";
const DATABASE_URL = "postgres://admin:password123@prod-db.internal:5432/myapp";

// Vulnerability: Weak crypto
import crypto from "crypto";
function hashPassword(password: string) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// Vulnerability: JWT decode without verify
import jwt from "jsonwebtoken";
app.get("/api/profile", (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwt.decode(token as string);
  res.json(decoded);
});

// Vulnerability: eval with user input
app.post("/api/calculate", (req, res) => {
  const expression = req.body.expression;
  const result = eval(expression);
  res.json({ result });
});

// Vulnerability: NoSQL injection
app.get("/api/products", (req, res) => {
  const category = req.query.category;
  const products = db.collection("products").find({ category: req.query.category });
  res.json(products);
});

// Vulnerability: SSRF
app.get("/api/fetch-url", (req, res) => {
  const url = req.query.url as string;
  fetch(url).then(r => r.text()).then(text => res.send(text));
});

// Vulnerability: Open Redirect
app.get("/login/callback", (req, res) => {
  const redirectUrl = req.query.redirect as string;
  res.redirect(redirectUrl);
});

// Vulnerability: Missing cookie security
app.post("/api/login", (req, res) => {
  res.cookie("session", "token-value", { maxAge: 86400000 });
  res.json({ success: true });
});

app.listen(3000);
