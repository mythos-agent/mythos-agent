import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { SqlInjectionScanner } from "../sql-injection-scanner.js";
import { CommandInjectionScanner } from "../command-injection-scanner.js";
import { XssDeepScanner } from "../xss-deep-scanner.js";
import { JwtScanner } from "../jwt-scanner.js";
import { PathScanner } from "../path-scanner.js";
import { SstiScanner } from "../ssti-scanner.js";
import { XxeScanner } from "../xxe-scanner.js";
import { DeserializationScanner } from "../deserialization-scanner.js";
import { OauthScanner } from "../oauth-scanner.js";
import { SessionScanner } from "../session-scanner.js";
import { OpenRedirectScanner } from "../open-redirect-scanner.js";
import { UploadScanner } from "../upload-scanner.js";
import { NosqlScanner } from "../nosql-scanner.js";
import { GraphqlScanner } from "../graphql-scanner.js";
import { HeadersScanner } from "../headers-scanner.js";
import { MemorySafetyScanner } from "../memory-safety-scanner.js";
import { WebsocketScanner } from "../websocket-scanner.js";
import { LoggingScanner } from "../logging-scanner.js";
import { ClickjackingScanner } from "../clickjacking-scanner.js";
import { InputValidationScanner } from "../input-validation-scanner.js";
import { CacheScanner } from "../cache-scanner.js";
import { PermissionScanner } from "../permission-scanner.js";

type Files = Record<string, string>;

const tmpDirs: string[] = [];

function fixture(files: Files): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sphinx-cov-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

// Rule IDs are emitted as `{prefix}:{id}` (e.g. "sqli:sqli-template-literal").
// Tests use includes() on the suffix to stay robust to prefix renames.
const hasRule = (findings: Array<{ rule: string }>, idFragment: string) =>
  findings.some((f) => f.rule.includes(idFragment));

describe("SqlInjectionScanner", () => {
  it("flags template-literal SQL with user input", async () => {
    const dir = fixture({
      "q.ts": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
    });
    const { findings } = await new SqlInjectionScanner().scan(dir);
    expect(hasRule(findings, "sqli-template-literal")).toBe(true);
  });

  it("flags Python f-string in cursor.execute", async () => {
    const dir = fixture({
      "app.py": 'cursor.execute(f"SELECT * FROM users WHERE name = {name}")',
    });
    const { findings } = await new SqlInjectionScanner().scan(dir);
    expect(hasRule(findings, "sqli-fstring-python")).toBe(true);
  });
});

describe("CommandInjectionScanner", () => {
  it("flags exec with template literal", async () => {
    const dir = fixture({
      "run.ts": "import { exec } from 'child_process';\nexec(`ls ${req.query.dir}`);",
    });
    const { findings } = await new CommandInjectionScanner().scan(dir);
    expect(hasRule(findings, "cmdi-exec-template")).toBe(true);
  });

  it("flags python os.system with f-string", async () => {
    const dir = fixture({
      "run.py": "import os\nos.system(f'cat {user_input}')",
    });
    const { findings } = await new CommandInjectionScanner().scan(dir);
    expect(hasRule(findings, "cmdi-python-os-system")).toBe(true);
  });
});

describe("XssDeepScanner", () => {
  it("flags innerHTML assignment from user input", async () => {
    const dir = fixture({
      "ui.ts": "el.innerHTML = req.query.message;",
    });
    const { findings } = await new XssDeepScanner().scan(dir);
    expect(hasRule(findings, "xss-dom-innerhtml")).toBe(true);
  });

  it("flags React dangerouslySetInnerHTML", async () => {
    const dir = fixture({
      "App.tsx": "export default () => <div dangerouslySetInnerHTML={{ __html: raw }} />;",
    });
    const { findings } = await new XssDeepScanner().scan(dir);
    expect(hasRule(findings, "xss-react-dangerously")).toBe(true);
  });
});

describe("JwtScanner", () => {
  it("flags jwt.verify with algorithm none", async () => {
    const dir = fixture({
      "auth.ts": "jwt.verify(token, secret, { algorithms: ['none'] });",
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(hasRule(findings, "jwt-none-algorithm")).toBe(true);
  });

  it("flags jwt.decode without verification", async () => {
    const dir = fixture({
      "auth.ts": "const payload = jwt.decode(token);",
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(hasRule(findings, "jwt-decode-without-verify")).toBe(true);
  });

  it("flags JWT stored in localStorage", async () => {
    const dir = fixture({
      "auth.ts": "localStorage.setItem('jwt', token);",
    });
    const { findings } = await new JwtScanner().scan(dir);
    expect(hasRule(findings, "jwt-stored-localstorage")).toBe(true);
  });
});

describe("PathScanner", () => {
  it("flags path.join with user-controlled segment", async () => {
    const dir = fixture({
      "read.ts": "const p = path.join('/data', req.params.file);",
    });
    const { findings } = await new PathScanner().scan(dir);
    expect(hasRule(findings, "path-traversal-join")).toBe(true);
  });
});

describe("SstiScanner", () => {
  it("flags Jinja2 Template rendering from user input", async () => {
    const dir = fixture({
      "app.py":
        "from jinja2 import Template\ntpl = Template(request.args.get('tpl'))\ntpl.render()",
    });
    const { findings } = await new SstiScanner().scan(dir);
    expect(hasRule(findings, "ssti-jinja2")).toBe(true);
  });
});

describe("XxeScanner", () => {
  it("flags Python libxml parser with external entities", async () => {
    const dir = fixture({
      "parse.py":
        "from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\nroot = etree.fromstring(data, parser)",
    });
    const { findings } = await new XxeScanner().scan(dir);
    expect(hasRule(findings, "xxe-")).toBe(true);
  });
});

describe("DeserializationScanner", () => {
  it("flags Python pickle.loads on untrusted data", async () => {
    const dir = fixture({
      "handler.py": "import pickle\nobj = pickle.loads(request.data)",
    });
    const { findings } = await new DeserializationScanner().scan(dir);
    expect(hasRule(findings, "deser-pickle-loads")).toBe(true);
  });

  it("flags yaml.load without safe_load", async () => {
    const dir = fixture({
      "cfg.py": "import yaml\ncfg = yaml.load(open('config.yml'))",
    });
    const { findings } = await new DeserializationScanner().scan(dir);
    expect(hasRule(findings, "deser-yaml-unsafe")).toBe(true);
  });
});

describe("OauthScanner", () => {
  it("flags implicit flow (response_type=token)", async () => {
    const dir = fixture({
      "oauth.ts":
        "const url = 'https://idp.example.com/authorize?response_type=token&client_id=x';",
    });
    const { findings } = await new OauthScanner().scan(dir);
    expect(hasRule(findings, "oauth-implicit-flow")).toBe(true);
  });
});

describe("SessionScanner", () => {
  it("flags session cookie without secure/httpOnly flags", async () => {
    const dir = fixture({
      "app.ts":
        "app.use(session({ secret: 'x', cookie: { httpOnly: false, secure: false, maxAge: 86400000 } }));",
    });
    const { findings } = await new SessionScanner().scan(dir);
    expect(hasRule(findings, "session-")).toBe(true);
  });
});

describe("OpenRedirectScanner", () => {
  it("flags res.redirect with raw user input", async () => {
    const dir = fixture({
      "redirect.ts": "app.get('/go', (req, res) => res.redirect(req.query.url));",
    });
    const { findings } = await new OpenRedirectScanner().scan(dir);
    expect(hasRule(findings, "redirect-")).toBe(true);
  });
});

describe("UploadScanner", () => {
  it("flags multer config missing fileFilter/limits", async () => {
    const dir = fixture({
      "upload.ts":
        "import multer from 'multer';\nconst upload = multer({ dest: 'uploads/' });\napp.post('/u', upload.single('file'), handler);",
    });
    const { findings } = await new UploadScanner().scan(dir);
    expect(hasRule(findings, "upload-")).toBe(true);
  });
});

describe("NosqlScanner", () => {
  it("flags Mongo $where with string expression", async () => {
    const dir = fixture({
      "query.ts": "db.users.find({ $where: `this.name == '${req.query.n}'` });",
    });
    const { findings } = await new NosqlScanner().scan(dir);
    expect(hasRule(findings, "nosql-")).toBe(true);
  });
});

describe("GraphqlScanner", () => {
  it("flags Apollo server with introspection enabled", async () => {
    const dir = fixture({
      "server.ts": "const server = new ApolloServer({ typeDefs, resolvers, introspection: true });",
    });
    const { findings } = await new GraphqlScanner().scan(dir);
    expect(hasRule(findings, "gql-introspection-enabled")).toBe(true);
  });
});

describe("HeadersScanner", () => {
  it("flags Express app without helmet (missing security headers)", async () => {
    const dir = fixture({
      "app.ts":
        "import express from 'express';\nconst app = express();\napp.get('/', (req, res) => res.send('hi'));\napp.listen(3000);",
    });
    const { findings } = await new HeadersScanner().scan(dir);
    expect(hasRule(findings, "header-")).toBe(true);
  });
});

describe("MemorySafetyScanner", () => {
  it("flags C strcpy (buffer overflow risk)", async () => {
    const dir = fixture({
      "main.c": "#include <string.h>\nvoid f(char* src){\n  char buf[16];\n  strcpy(buf, src);\n}",
    });
    const { findings } = await new MemorySafetyScanner().scan(dir);
    expect(hasRule(findings, "mem-")).toBe(true);
  });

  it("flags Rust unsafe block", async () => {
    const dir = fixture({
      "main.rs":
        "fn main() {\n    unsafe {\n        let p: *mut i32 = std::ptr::null_mut();\n        *p = 42;\n    }\n}",
    });
    const { findings } = await new MemorySafetyScanner().scan(dir);
    expect(hasRule(findings, "mem-rust-unsafe")).toBe(true);
  });
});

describe("WebsocketScanner", () => {
  it("flags WebSocket server without auth check", async () => {
    const dir = fixture({
      "ws.ts":
        "import { WebSocketServer } from 'ws';\nconst wss = new WebSocketServer({ port: 8080 });\nwss.on('connection', (ws) => {\n  ws.on('message', (m) => ws.send(m));\n});",
    });
    const { findings } = await new WebsocketScanner().scan(dir);
    expect(hasRule(findings, "ws-")).toBe(true);
  });
});

describe("LoggingScanner", () => {
  it("flags logging of sensitive fields", async () => {
    const dir = fixture({
      "auth.ts": "console.log('user logged in', { email, password });",
    });
    const { findings } = await new LoggingScanner().scan(dir);
    expect(hasRule(findings, "log-")).toBe(true);
  });
});

describe("ClickjackingScanner", () => {
  it("flags window.opener usage without noopener", async () => {
    const dir = fixture({
      "ui.ts":
        "const w = window.open(url);\nif (w) { w.opener.location = 'https://evil.example'; }",
    });
    const { findings } = await new ClickjackingScanner().scan(dir);
    expect(hasRule(findings, "cj-")).toBe(true);
  });
});

describe("InputValidationScanner", () => {
  it("flags Express handler using body directly in a DB query", async () => {
    const dir = fixture({
      "routes.ts":
        "app.post('/users', (req, res) => {\n  const name = req.body.name;\n  db.query(`INSERT INTO users VALUES (${name})`);\n});",
    });
    const { findings } = await new InputValidationScanner().scan(dir);
    expect(hasRule(findings, "input-")).toBe(true);
  });
});

describe("CacheScanner", () => {
  it("flags caching of authenticated responses", async () => {
    const dir = fixture({
      "handler.ts":
        "app.get('/profile', authMiddleware, (req, res) => {\n  res.setHeader('Cache-Control', 'public, max-age=3600');\n  res.json({ email: user.email });\n});",
    });
    const { findings } = await new CacheScanner().scan(dir);
    expect(hasRule(findings, "cache-")).toBe(true);
  });
});

describe("PermissionScanner", () => {
  it("flags world-writable chmod (0o777)", async () => {
    const dir = fixture({
      "setup.ts": "import fs from 'fs';\nfs.chmodSync('/tmp/data', 0o777);",
    });
    const { findings } = await new PermissionScanner().scan(dir);
    expect(hasRule(findings, "perm-")).toBe(true);
  });
});
