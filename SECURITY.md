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
- **Break-fix releases** (critical non-security fixes) tagged with `[breakfix]` and auto-applied the same way, unless an operator has set `auto_update.breakfix: false`. A fix for a vulnerability always ships as a security release, never as a break-fix, so it reaches every box
- **Automatic updates cross minor versions, but never a breaking release.** A box on 0.10.x is automatically moved to a 0.11.x security release, as long as no release between them is marked breaking (one that changes operator workflows or could make an existing project, manifest, compose file, command line or upload method fail). Breaking releases bump the minor version and are tagged `[breaking]`. Automatic updates never cross a major version

## Scope

This policy covers:
- The boxmunge CLI and Python codebase
- The bootstrap scripts (`init-host.sh`, hardening scripts)
- The system container (Dockerfile, compose)
- The restricted shell and SFTP handler
- The MCP server
- The `boxmunge` client published on PyPI (`cli/`)
- The public update-discovery service (`services/version-check/`)

Out of scope:
- Third-party dependencies (report to their maintainers, but let us know if it affects boxmunge)
- Vulnerabilities in user-authored application code or its dependencies. boxmunge applies container-level hardening by default; see `docs/on-server/SECURITY.md` for the model.

## Contributions and the security floor

boxmunge does not merge changes that lower its default security posture. Capabilities that add
attack surface are offered as explicit opt-in choices or plugins instead. See the principles in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Supported Versions

Only the latest release is supported with security fixes. We don't backport to older versions — upgrade to get the fix.

When a breaking release stands between a box and a security or break-fix release, auto-update
cannot install the fix, because doing so could break the box's projects. The operator reads the
breaking release's notes, makes any changes it asks for, and runs `upgrade`.
