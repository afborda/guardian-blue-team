# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Guardian Blue Team, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email:** Send details to security@example.com
2. **GitHub Security Advisories:** Use [GitHub's private reporting](https://github.com/afborda/guardian-blue-team/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix Release:** Within 2 weeks for critical issues

### Scope

The following are in scope:
- Remote code execution
- Authentication bypass
- SSH key exposure
- Privilege escalation
- SQL injection (if applicable)
- Command injection via playbook actions

### Out of Scope

- Denial of service (Guardian is self-hosted)
- Issues requiring physical access to the host
- Social engineering attacks
- Vulnerabilities in dependencies (report to upstream)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |
