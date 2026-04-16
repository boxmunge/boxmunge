# boxmunge Trust Model

How boxmunge handles security boundaries, isolation, and access control.

---

## Single-Owner Model

boxmunge assumes all projects on a box belong to one person or entity. There is no per-project access control and no multi-user IAM.

The `deploy` user can operate on any project — this is by design, not a gap. The `supervisor` user has full shell access with sudo.

## What We Isolate

**Platform tooling** runs inside containers for blast-radius containment:
- **Caddy** (reverse proxy) — containerised, read-only filesystem, all capabilities dropped except NET_BIND_SERVICE
- **boxmunge-system** (age, rclone) — containerised, read-only, no capabilities, non-root user

**Secrets** are file-permission isolated — each project's `secrets.env` is mode 600, owned by the deploy user. The deploy user can read any project's secrets (single-owner assumption).

**Logs and state** are per-project by default. The `boxmunge log` command scopes to a single project unless `--all` is passed. This prevents agent context pollution, not security isolation.

## What We Don't Isolate

- **Network** — projects share the `boxmunge-proxy` Docker network and can technically reach each other. Acceptable for single-owner.
- **Docker socket** — the deploy user has access via group membership. Necessary for container management.
- **Backups** — the deploy user can trigger backup/restore for any project.

## Explicitly Out of Scope

- Multi-tenant isolation
- Per-project credentials / RBAC
- Network policies between projects
- Per-user audit trails (there's one "who")

## Host Hardening

boxmunge hardens the VPS as part of installation:

- **UFW firewall** — deny all inbound except SSH, HTTP, HTTPS
- **CrowdSec** — community threat intelligence IPS
- **fail2ban** — brute-force protection
- **Kernel hardening** — sysctl overrides (SYN cookies, ASLR, restricted BPF, etc.)
- **AIDE** — file integrity monitoring on the control plane
- **Auditd** — kernel audit logging for privilege escalation and sensitive file changes
- **AppArmor** — tightened profiles for Caddy and system containers
- **Unattended upgrades** — automatic OS security patches
- **Automatic security updates** — boxmunge checks for its own security releases every 6 hours

## Security Releases

Security-tagged releases are applied automatically within 12 hours. The user never needs to check CVE reports. The `boxmunge upgrade` flow handles stashing, migration, and validation automatically.
