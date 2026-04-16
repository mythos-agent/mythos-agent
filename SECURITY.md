# Security Policy

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in sphinx-agent, please report it responsibly:

1. **Email:** Send details to **security@sphinx-agent.dev**
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Critical issues within 7 days, others within 30 days
- **Disclosure:** Coordinated disclosure after fix is released

## Scope

This security policy applies to:
- The sphinx-agent CLI tool (`src/`)
- The VS Code extension (`vscode-extension/`)
- The MCP server (`src/mcp/`)
- The REST API server (`src/server/`)
- GitHub Actions (`action/`)
- Docker images

## Out of Scope

- Demo/example code (`demo-vulnerable-app/` is intentionally vulnerable)
- Third-party tools integrated via subprocess (Semgrep, Trivy, etc.)
- Vulnerabilities in dependencies (report to the respective maintainers)

## Security Measures

sphinx-agent follows these security practices:
- All subprocess calls use `spawnSync` with argument arrays (no shell injection)
- File operations include path traversal prevention
- API server binds to 127.0.0.1 by default
- No secrets in source code (API keys via environment variables)
- Regular code reviews (3 completed, 35 issues fixed)
- 96 automated tests

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Active |
| 1.x     | ⚠️ Security fixes only |
| < 1.0   | ❌ Not supported |

## Recognition

We appreciate security researchers who help keep sphinx-agent safe. Reporters will be credited in the release notes (unless they prefer to remain anonymous).
