# boxmunge Trust Model

How boxmunge handles security boundaries, isolation, and access control.

---

## Threat Model

boxmunge's defences are calibrated against a specific set of attackers. Future evolutions may extend this scope; today, severity assessments assume the model below.

### In scope

- **Network-level third-party attackers** — scanning, brute-force SSH, DDoS, malicious traffic targeting the public surface. Mitigations: UFW, CrowdSec, fail2ban, kernel hardening, key-only SSH on a non-default port.
- **Supply-chain compromise of platform releases** — a tampered boxmunge release reaching the box. Mitigations: SHA256 checksums on all releases; cosign signing planned.
- **Container-escape blast radius** — a compromised user container should not trivially own the host. Mitigations: per-service capability drops, `no-new-privileges`, `pids_limit`, Tini, the host-level platform-container hardening.

### Out of scope (current product)

- **Malicious operators** — anyone with `supervisor` or `deploy` SSH access is fully trusted. The restricted shell is a UX guard against accidents and a reduction in agent context-pollution surface, not a privilege boundary against a determined attacker who already has a key.
- **Malicious agents / MCP tools** — at present, agents and tools invoked through the deploy shell or MCP are treated equivalently to operators. A future product evolution may split agent trust from operator trust; today they are the same principal.

### Single human operator

The same person holds keys to `deploy` and `supervisor`. There is no per-project access control, no per-tenant credential isolation, no audit of "which operator did this." If you need any of those, boxmunge is the wrong tool.

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
- **Docker group** — the deploy user is in the `docker` group, which is effectively equivalent to root on the host (a user can mount the host filesystem via `docker run -v /:/host`). This is an intentional trade-off: the deploy user needs to run `docker compose` for deployments, and Docker's permission model requires group membership. The restricted shell limits what the deploy user does *directly*, but it is not a privilege boundary against a determined attacker who already has SSH access as deploy. Key-only authentication is the real perimeter.
- **Backup encryption key** — the deploy user can read the age identity key at `/opt/boxmunge/config/backup.key` (mode 640, group deploy). This is required for backup and restore operations to work without sudo. An authenticated deploy user can decrypt any backup snapshot.
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

## Per-Project Container Hardening

In addition to the host-level and platform-container hardening above, boxmunge applies a per-service hardening layer to every user project, silently and by default.

### What's applied (profile: `default`)

Every service in `compose.boxmunge.yml` receives:

- `security_opt: ["no-new-privileges:true"]` — blocks setuid / file-cap escalation inside the container.
- `init: true` — Tini for signal handling and zombie reaping.
- `pids_limit: 512` — kills fork bombs and exec storms.
- `cap_drop` of dangerous capabilities not in Docker's default deny set: `NET_ADMIN, SYS_PTRACE, SYS_MODULE, SYS_RAWIO, SYS_TIME, SYS_BOOT, MAC_ADMIN, MAC_OVERRIDE, MKNOD, AUDIT_WRITE, WAKE_ALARM, BLOCK_SUSPEND, LEASE, NET_RAW`.

These defaults are the **silent floor**. Existing v1 manifests need no edits — the v1→v2 migration adds nothing. The next deploy applies the protections automatically.

### How to relax a protection

Add a `security:` block to your `manifest.yml`. Project-level applies to all services; per-service overrides win.

Strongly preferred: keep `profile: default` and tweak only the field that needs relaxing.

```yaml
security:
  cap_add: [NET_RAW]      # re-add NET_RAW for ping/traceroute health checks
  pids_limit: 2048        # raise the process ceiling
```

Last-resort: turn the whole posture off for one service. Requires a non-empty `reason`. The reason is reproduced in deploy logs and `boxmunge security` output.

```yaml
services:
  web:
    security:
      profile: "off"
      reason: "deliberate honeypot service, see issue #42"
```

Quote `"off"`: PyYAML parses unquoted `off` as YAML 1.1 boolean `False`,
which the validator catches with a targeted error, but writing the quotes
in the first place avoids the round-trip.

A deploy-time `[WARNING] SECURITY OFF` message is emitted on every `stage`, `promote`, `deploy`, `prod-deploy`, `resume`, and `upgrade` for any service on `profile: off`. The warning is repeated by design — the shortest path to making it go away is removing `profile: off` from the manifest.

### Profile ladder

`off` → `default` → `strict` (Tier 3) → `paranoid` (Tier 8). `strict` and `paranoid` are reserved names; manifests using them today fail validation. They will arrive in future boxmunge releases with explicit migration guidance.

### Introspection

```text
boxmunge security <project>           # human-readable
boxmunge security <project> --json    # machine-readable (used by MCP)
boxmunge check <project>              # read-only health check, single project
boxmunge check-all --read-only        # read-only health check, every project
```

Shows the effective posture per service after profile + override resolution.

`boxmunge check-all` (without `--read-only`) is **state-mutating**: it
writes per-project health JSON, may call `compose_down` on critical
failures, and emits Pushover notifications. That form is what the systemd
health timer drives. Use `--read-only` for an introspection-only run that
prints the same report with no side effects.

## Security Releases

Security-tagged releases are applied automatically within 12 hours. The `boxmunge upgrade` flow handles stashing, migration, and validation automatically. Release artifacts are signed with cosign when available; SHA256 checksums are always provided.
