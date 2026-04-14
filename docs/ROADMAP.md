# sphinx-agent Roadmap: From Scanner to Autonomous Security Agent

## Where We Are Today (v1.0)

sphinx-agent is an AI-powered security scanner with 10 CLI commands, 40+ source files, and 54 tests. It can:
- Pattern scan code in 6 languages (25+ rules)
- Detect 22 types of hardcoded secrets
- Scan dependencies against OSV database (10 lockfile formats)
- Scan Docker, Terraform, and Kubernetes IaC (13 rules)
- Use Claude/OpenAI for AI deep analysis and vulnerability chaining
- Trace taint flows from sources to sinks
- Answer natural language security questions
- Auto-generate patches for vulnerabilities
- Watch files continuously, serve a web dashboard
- Enforce policy-as-code with compliance mapping (SOC2/HIPAA/PCI/OWASP)

## What Mythos Can Do (That We Can't Yet)

Based on public information about Anthropic's Mythos model and Project Glasswing:

1. **Autonomous zero-day discovery** — finds previously unknown vulnerabilities in production software (OS kernels, browsers, network stacks)
2. **Multi-step exploit chain construction** — doesn't just find individual bugs, but constructs complete attack paths across system boundaries
3. **Deep code understanding** — reasons about complex program state, concurrency, memory management, and type confusion
4. **Cross-component analysis** — traces vulnerabilities across process boundaries, APIs, and system calls
5. **Automated patch generation with validation** — generates fixes and verifies they don't break functionality

## The Gap: What We Need to Build

### Level 1: Deep Code Understanding (current → production-grade)
**Goal:** Move from regex pattern matching to true semantic code analysis.

| Capability | Current | Target |
|-----------|---------|--------|
| Pattern matching | Regex rules | Regex + Semgrep + tree-sitter AST |
| Data flow | AI prompt-based taint tracking | Deterministic taint graphs + AI reasoning |
| Cross-file analysis | AI reads files on demand | Pre-built dependency/call graphs |
| Control flow | None | CFG construction per function |
| Type understanding | None | Type-aware analysis (TS/Python types) |

**What to build:**
- `src/analysis/ast-parser.ts` — tree-sitter integration for multi-language AST parsing
- `src/analysis/call-graph.ts` — build inter-procedural call graphs
- `src/analysis/taint-graph.ts` — deterministic taint propagation (source → transform → sink)
- `src/analysis/type-resolver.ts` — resolve types to understand what data reaches where
- Integrate Semgrep as a library (spawn `semgrep --json`) for rule-based scanning alongside regex

### Level 2: Autonomous Exploration Agent (new capability)
**Goal:** Agent that navigates a codebase like a security researcher — forms hypotheses, investigates, and finds novel issues.

| Capability | Current | Target |
|-----------|---------|--------|
| Agent strategy | Single prompt → scan | Multi-phase: recon → hypothesis → investigate → verify |
| Code navigation | read_file, search_code | + AST navigation, jump-to-definition, find-references |
| Memory | Per-session only | Persistent codebase knowledge graph |
| Reasoning | Single Claude call per file | Multi-turn agentic loop with backtracking |

**What to build:**
- `src/agent/autonomous-scanner.ts` — multi-phase agentic scanner:
  - Phase A: Reconnaissance — map entry points, auth boundaries, data stores
  - Phase B: Hypothesis — generate vulnerability hypotheses from architecture
  - Phase C: Investigation — deep-dive each hypothesis with tool use
  - Phase D: Verification — confirm exploitability, assess severity
- `src/agent/tools-advanced.ts` — enhanced agent tools:
  - `jump_to_definition` — follow symbol to its declaration
  - `find_references` — find all call sites of a function
  - `get_ast` — return AST subtree for a function/class
  - `get_call_graph` — show what calls what
  - `run_test` — execute a test to verify behavior
- `src/agent/knowledge-graph.ts` — persistent codebase knowledge:
  - Entry points (API routes, event handlers, CLI commands)
  - Authentication boundaries
  - Data stores and their access patterns
  - Trust boundaries between components

### Level 3: Advanced Vulnerability Discovery (beyond patterns)
**Goal:** Find vulnerability classes that pattern matching fundamentally cannot detect.

| Vulnerability Class | How to Detect |
|-------------------|---------------|
| **Business logic flaws** | AI reasons about intended vs actual behavior using specs/comments |
| **Race conditions / TOCTOU** | Static analysis of shared state + concurrent access patterns |
| **Authentication bypasses** | Map all auth checks, find paths that skip them |
| **Authorization flaws (IDOR)** | Trace object references from user input to data access |
| **Cryptographic misuse** | Verify correct IV/nonce handling, key derivation, mode selection |
| **Deserialization attacks** | Track untrusted data to deserialization sinks |
| **Prototype pollution** | JS/TS-specific: track object merges with user input |
| **Memory safety** | For C/C++/Rust unsafe: buffer overflows, use-after-free (via AI reasoning on pointer analysis) |

**What to build:**
- `src/scanner/business-logic-scanner.ts` — AI analyzes code comments, docs, and tests to understand intended behavior, then flags deviations
- `src/scanner/concurrency-scanner.ts` — detect shared mutable state accessed without synchronization
- `src/scanner/auth-scanner.ts` — map all auth/authz enforcement points, find bypass paths
- `src/scanner/crypto-scanner.ts` — verify correct usage of crypto primitives (not just "uses MD5" but "uses AES-CBC without HMAC")
- Expand built-in rules to 100+ covering all CWE Top 25

### Level 4: Vulnerability Chaining Engine (upgrade)
**Goal:** Move from AI-only chaining to a graph-based engine augmented by AI.

| Capability | Current | Target |
|-----------|---------|--------|
| Chain detection | Single AI prompt | Graph traversal + AI verification |
| Chain types | Source → Sink | Multi-step: Vuln A → enables Vuln B → leads to Impact C |
| Scoring | AI-estimated severity | CVSS v4 vector calculation |
| Visualization | Terminal text | Interactive HTML graph |

**What to build:**
- `src/chain/vuln-graph.ts` — directed graph of vulnerabilities with edges representing enablement
- `src/chain/chain-solver.ts` — graph traversal algorithm to find all exploitable paths
- `src/chain/cvss-calculator.ts` — compute CVSS v4 scores for individual and chained vulns
- `src/report/chain-visualizer.ts` — interactive D3.js-based attack path visualization in HTML report

### Level 5: Dynamic Analysis Integration (DAST)
**Goal:** Combine static analysis with runtime testing for confirmation.

| Capability | Current | Target |
|-----------|---------|--------|
| Analysis type | Static only | Static + Dynamic |
| Confirmation | AI assessment | Proof-of-concept exploit generation |
| Fuzzing | None | AI-guided fuzzing of suspicious inputs |
| API testing | None | Auto-discover and test API endpoints |

**What to build:**
- `src/dast/endpoint-discoverer.ts` — parse route definitions to find all API endpoints
- `src/dast/fuzzer.ts` — AI-guided fuzzing: generate targeted payloads based on static findings
- `src/dast/exploit-generator.ts` — generate proof-of-concept requests that demonstrate vulnerabilities
- `src/dast/api-tester.ts` — automated API security testing (auth checks, rate limits, input validation)
- Integration: `sphinx-agent scan --dynamic` flag that starts the app and tests it

### Level 6: Cross-System Analysis
**Goal:** Analyze interactions between services, not just individual codebases.

**What to build:**
- `src/scanner/api-contract-scanner.ts` — analyze OpenAPI/GraphQL schemas for security issues
- `src/scanner/microservice-mapper.ts` — map inter-service communication from docker-compose, K8s manifests, or code
- `src/scanner/trust-boundary-analyzer.ts` — identify where trust boundaries should exist between services
- Support for scanning monorepos with multiple services: `sphinx-agent scan --monorepo`

### Level 7: Validated Auto-Remediation
**Goal:** Generate patches that are verified to fix the vulnerability without breaking functionality.

| Capability | Current | Target |
|-----------|---------|--------|
| Fix generation | AI writes patch | AI writes patch + generates test |
| Validation | None (user reviews) | Auto-run tests, verify fix, check for regressions |
| Fix types | Code changes only | Code + config + dependency updates |

**What to build:**
- `src/agent/fix-validator.ts` — after generating a fix:
  1. Apply patch to temp branch
  2. Run existing tests (if any)
  3. Generate a new test that verifies the fix
  4. Run the new test
  5. Check that the vulnerability is no longer detected
  6. Report: "Fix verified" or "Fix failed"
- `src/agent/dependency-fixer.ts` — for vulnerable dependencies: find safe version, test upgrade compatibility

---

## Implementation Phases

### Phase 1: Foundation (4-6 weeks)
**Make the static analysis production-grade.**

1. Integrate tree-sitter for AST parsing (TS/JS/Python/Go)
2. Integrate Semgrep as a scanning backend
3. Build deterministic taint graph construction
4. Build inter-procedural call graph
5. Expand rules to 100+ (CWE Top 25 full coverage)
6. Add CVSS v4 scoring
7. Improve false positive rate to <10%

### Phase 2: Autonomous Agent (4-6 weeks)
**Build the multi-phase security research agent.**

1. Implement the 4-phase autonomous scanner (recon → hypothesis → investigate → verify)
2. Add advanced agent tools (jump-to-definition, find-references, get-ast)
3. Build codebase knowledge graph
4. Add business logic and auth/authz scanning
5. Add crypto and concurrency analysis

### Phase 3: Dynamic Analysis (4-6 weeks)
**Add runtime testing capabilities.**

1. Endpoint discovery from code
2. AI-guided fuzzing
3. Proof-of-concept exploit generation
4. API security testing
5. Static+Dynamic finding correlation

### Phase 4: Chain Engine + Visualization (2-4 weeks)
**Upgrade vulnerability chaining to graph-based.**

1. Vulnerability graph construction
2. Chain solver algorithm
3. Interactive attack path visualization
4. CVSS v4 chain scoring

### Phase 5: Cross-System + Remediation (4-6 weeks)
**Scale to multi-service architectures.**

1. API contract scanning
2. Microservice mapping
3. Trust boundary analysis
4. Validated auto-remediation with test generation
5. Dependency auto-upgrade with compatibility testing

---

## Competitive Positioning

| Capability | Semgrep | CodeQL | Snyk | Nuclei | sphinx-agent (target) |
|-----------|---------|--------|------|--------|----------------------|
| Pattern matching | Best-in-class | Good | Good | Template-based | Semgrep + custom |
| Semantic analysis | Limited | Strong (manual queries) | ML-assisted | None | AI-native (autonomous) |
| Cross-file taint | Pro only (paid) | Yes (complex setup) | Limited | None | Deterministic + AI |
| Business logic | No | No | No | No | **Yes (AI reasoning)** |
| Vuln chaining | No | No | No | No | **Yes (graph + AI)** |
| Dynamic analysis | No | No | No | Yes (templates) | **AI-guided fuzzing** |
| Auto-remediation | Limited | No | Fix PRs | No | **Validated patches** |
| NL queries | No | No | No | No | **Yes (sphinx-agent ask)** |
| Cross-service | No | No | No | No | **Yes (planned)** |
| Local models | N/A | N/A | N/A | N/A | **Yes (Ollama/vLLM)** |

## The Vision

sphinx-agent starts as a scanner. It becomes a **security research agent** — an autonomous system that:

1. **Understands** your codebase deeply (architecture, data flows, trust boundaries)
2. **Hunts** for vulnerabilities like a senior penetration tester (hypothesize → investigate → verify)
3. **Chains** individual findings into real attack paths
4. **Proves** exploitability with generated proof-of-concepts
5. **Fixes** vulnerabilities and verifies the fixes work
6. **Guards** continuously — watching every commit, every PR, every deployment

Mythos does this for 40 organizations. sphinx-agent does it for everyone.
