# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in boxmunge, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **boxmunge@pm.me** (or open a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository if available).

Include:
- A description of the vulnerability
- Steps to reproduce
- Your assessment of severity and impact
- Any suggested fix (optional but appreciated)

## What to expect

- **Acknowledgement** within 72 hours
- **Assessment and fix timeline** communicated within 1 week
- **Security releases** tagged with `[security]` and auto-applied to deployed instances within 12 hours via `boxmunge auto-update`

## Scope

This policy covers:
- The boxmunge CLI and Python codebase
- The bootstrap scripts (`init-host.sh`, hardening scripts)
- The system container (Dockerfile, compose)
- The restricted shell and SFTP handler
- The MCP server

Out of scope:
- Third-party dependencies (report to their maintainers, but let us know if it affects boxmunge)
- User-deployed projects running on boxmunge (that's your responsibility)

## Supported Versions

Only the latest release is supported with security fixes. We don't backport to older versions — upgrade to get the fix.
