# boxmunge Architecture

How boxmunge is structured -- components, layout, networking, privilege model, and data flows.

---

## Overview

boxmunge is a minimalist VPS hosting framework for running multiple Docker Compose web projects on a single server. It provides a managed platform layer without the overhead of a full PaaS.

Key features:

- **Restricted deploy shell** -- agents connect as `deploy` and can only run boxmunge commands; no filesystem browsing, no raw docker, no shell utilities
- **Standard project layout and manifest** -- every project declares its services, routing, backup strategy, and health checks in `manifest.yml`
- **Staging environment** -- `stage` deploys alongside production at `staging.<hostname>` for verification before `promote`
- **CLI-managed secrets** -- `secrets` manages project-level and host-level secrets; no manual file editing
- **Caddy reverse proxy in Docker** -- automatic HTTPS via Let's Encrypt, containerised for blast-radius containment
- **Python CLI** -- `boxmunge` command covers the full lifecycle: deploy, stage, promote, backup, restore, health check
- **Encrypted backups with mandatory restore** -- all backups encrypted with age; restore script required if backup type is not `none`
- **Health checking with Pushover alerting** -- three-layer checks (Docker, HTTP, smoke test) with graduated alert logic
- **On-server docs via agent-help** -- documentation accessible via `agent-help <topic>` so agents can orient without filesystem access

---

## Directory Layout

```
/opt/boxmunge/
  bin/                        # boxmunge CLI and helpers (root:root 755)
  config/                     # host-level config (root:deploy 750)
    boxmunge.yml              # main host configuration
    backup.key                # backup encryption key (root:deploy 640)
    secrets/                  # host-level secrets (deploy:deploy 600)
  caddy/                      # Caddy container config (root:root 755)
    compose.yml               # Caddy's own compose file
    Caddyfile                 # main Caddyfile (imports sites/*.conf)
    sites/                    # generated per-project Caddy configs
  projects/                   # project directories (deploy:deploy 755)
    <project-name>/
      manifest.yml            # project manifest (includes id, source)
      compose.yml             # project-authored Docker Compose file
      compose.boxmunge.yml    # generated overlay (networking, env, limits)
      project.env             # ships with bundle (non-secret config)
      secrets.env             # CLI-managed secrets (boxmunge secrets)
      caddy.override.conf     # optional: verbatim Caddy config escape hatch
      boxmunge-scripts/       # project's integration scripts
        smoke.sh
        backup.sh
        restore.sh
        migrate.sh
      backups/                # encrypted local backup archives
      data/                   # persistent volume mounts
      repo/                   # git clone (source: git projects only)
  inbox/                      # uploaded bundles awaiting deployment
  state/                      # operational state (deploy:deploy 755)
    health/                   # per-project health state JSON
    deploy/                   # per-project deploy state JSON
    staging/                  # per-project staging state
  docs/                       # on-server documentation (root:root 755)
  logs/                       # boxmunge operational logs (deploy:deploy 755)
    boxmunge.log
```

For project-level conventions (manifest format, script contracts, env file conventions), run `agent-help conventions`.

---

## Networking Model

### Caddy in Docker

Caddy runs as a Docker container, not as a host process. This contains the blast radius: a misconfigured Caddy cannot modify the host filesystem or escalate privileges.

The Caddy container is configured with:

- Read-only filesystem (`read_only: true`)
- All capabilities dropped (`cap_drop: ALL`), with only `NET_BIND_SERVICE` re-added
- Ports 80 and 443 bound on the host
- Config files mounted read-only

### Shared Proxy Network

The Docker network `boxmunge-proxy` connects Caddy to project containers that need external access. Caddy and the routable project services all join this network.

Traffic flow:

```
Internet
  -> :443 (host)
  -> Caddy container (boxmunge-proxy network)
  -> project container (boxmunge-proxy network, alias: <project>-<service>)
```

Project containers are reachable from Caddy using project-scoped network aliases, for example `myapp-frontend` or `myapp-backend`. Services marked `internal: true` in the manifest are excluded from the proxy network and are not reachable from Caddy or other projects.

### Staging Network

When a project is staged, its containers run alongside production on a separate staging network. Caddy routes `staging.<hostname>` to the staged containers. Promoting tears down staging and replaces production. Unstaging tears down staging without affecting production.

### Config Generation

`deploy` (and `stage`) reads the `services` block in `manifest.yml` and generates two files:

1. Caddy site config -- reverse proxy rules, ordered by route specificity
2. `compose.boxmunge.yml` -- Docker Compose overlay that attaches routable services to `boxmunge-proxy` with their aliases, injects env_files, and applies resource limits

The project's own `compose.yml` does not need to reference boxmunge networking at all. The overlay is the platform's concern.

If a project contains `caddy.override.conf`, boxmunge uses it verbatim instead of generating config. A notice is logged when this escape hatch is active.

---

## Privilege Model

boxmunge uses two users with distinct access levels:

### deploy (restricted shell)

The `deploy` user runs a restricted boxmunge shell. Agents connect as `deploy`.

- Can **only** run `boxmunge` commands -- no `ls`, `cat`, `cd`, `docker`, or any other shell command
- Cannot browse the filesystem or read files directly
- Cannot run `sudo`
- Documentation is accessed via `agent-help <topic>`, not by reading files

This is the complete interface for agents. There is nothing else.

### supervisor (bash + sudo)

The `supervisor` user has a standard bash shell with sudo access, intended for human administrators performing tasks that require filesystem access or system-level operations.

- Full shell access
- Can run `sudo` for administrative tasks
- Used for troubleshooting that requires inspecting files, Docker state, or system configuration

### Filesystem Ownership

**root** owns the control plane:

| Path | Permissions |
|------|-------------|
| `/opt/boxmunge/bin/` | root:root 755 |
| `/opt/boxmunge/config/` | root:deploy 750 |
| `/opt/boxmunge/caddy/` | root:root 755 |
| `/opt/boxmunge/docs/` | root:root 755 |

**deploy** owns the data plane:

| Path | Permissions |
|------|-------------|
| `/opt/boxmunge/projects/` | deploy:deploy 755 |
| `/opt/boxmunge/inbox/` | deploy:deploy 755 |
| `/opt/boxmunge/state/` | deploy:deploy 755 |
| `/opt/boxmunge/logs/` | deploy:deploy 755 |

---

## Deploy Flow

### Source Resolution

boxmunge supports two project sources, declared in `manifest.yml` via the `source` field:

- **`bundle`** -- project files uploaded as a tar.gz bundle via scp to the inbox
- **`git`** -- project cloned from a git repo specified by `repo` and `ref` in the manifest

### Deploy Steps

`deploy <project>` executes these steps in order:

1. Resolve source -- locate bundle in inbox or pull from git repo
2. Validate manifest -- schema check, required fields (`id`, `source`, `project`, `hosts`, services), backup/restore pairing
3. Pre-deploy snapshot -- encrypted backup of current state (unless `--no-snapshot`)
4. Pre-deploy command -- run `deploy.pre_deploy` from manifest if defined (e.g., migrations)
5. Generate configs -- write Caddy site config and compose overlay (networking, env_files, resource limits)
6. Start containers -- `docker compose up -d` with overlay
7. Reload Caddy -- graceful, zero-downtime
8. Smoke test -- run `boxmunge-scripts/smoke.sh`, interpret exit code
9. Record state -- write deploy state JSON atomically
10. Log the deployment -- append to boxmunge operational log

If any step fails, the deploy stops and reports the failure. No automatic rollback -- the operator or agent decides what to do next.

### Staging Flow

`stage <project>` follows the same steps but deploys to the staging environment at `staging.<hostname>`. After verification:

- `promote <project>` -- tears down staging, deploys to production
- `unstage <project>` -- tears down staging, production unchanged

Staging state is tracked under `state/staging/`.

---

## Secrets Storage

Secrets are managed via `secrets` and stored in env files:

- **Project-level secrets** -- stored in `projects/<project>/secrets.env`, injected into containers via the compose overlay
- **Host-level secrets** -- stored in `config/secrets/`, available to all projects, managed with `secrets --host`

Secrets are never edited manually. The CLI handles file creation, permissions, and format.

`project.env` (which ships with the bundle) is for non-secret configuration. `secrets.env` (CLI-managed) is for credentials and sensitive values. Both are injected via the generated compose overlay.

---

## State Management

Operational state is stored as JSON files under `/opt/boxmunge/state/`:

- `state/health/<project>.json` -- last check time, status, consecutive failure count, alert state, failure reason
- `state/deploy/<project>.json` -- current ref/bundle, deploy timestamp, pre-deploy snapshot filename, recent history
- `state/staging/<project>/` -- staging environment state

All state writes are atomic: the new content is written to a temporary file in the same directory, then renamed into place with `os.rename()`. This prevents partial reads if a check or deploy runs concurrently.

---

## Backup Model

Projects declare their backup type in `manifest.yml`:

| Type | Meaning |
|------|---------|
| `none` | No backup |
| `postgres` | PostgreSQL dump |
| `mysql` | MySQL dump |
| `files` | File-based backup |
| `custom` | Custom backup script |

If `type` is anything other than `none`, both `dump_command` and `restore_command` are mandatory. boxmunge refuses to accept a manifest with a backup type but no restore script -- a backup you cannot restore is not a backup.

Backup flow:

1. Run the dump command from the manifest
2. Tar and compress the output
3. Encrypt with age using the backup key
4. Write atomically to `<project>/backups/<project>-<ISO8601>.tar.gz.age`
5. Prune local archives beyond the configured retention count
6. Log the backup

Off-box sync uses rclone to push encrypted archives to the configured remote. Since archives are encrypted before leaving the box, the remote is untrusted storage.

---

## Health Checking

Checks run in three layers:

1. **Docker healthcheck** -- read container health status via Docker
2. **HTTP endpoint** -- for services declaring `health.endpoint`, HTTP GET through Caddy (verifies the full public chain including TLS)
3. **Smoke test** -- `boxmunge-scripts/smoke.sh` with graduated exit codes:

| Exit code | Meaning | boxmunge response |
|-----------|---------|-------------------|
| 0 | Healthy | Clear any failure state, send recovery alert if previously failing |
| 1 | Warning/error | Alert after N consecutive failures (default 3); re-alert if message changes |
| 2 | Critical failure | Alert immediately, stop containers, enter `critical_stopped` state |

A project in `critical_stopped` state will not restart automatically. It requires an explicit `deploy` to recover.

---

## Automation

Recurring operations run via systemd timers:

| Timer | Schedule | Command |
|-------|----------|---------|
| `boxmunge-health.timer` | Every 5 minutes | `check-all` |
| `boxmunge-backup.timer` | Daily at 02:00 | `backup-all` |
| `boxmunge-backup-sync.timer` | Daily at 03:00 | `backup-sync` |

All timers use `Persistent=true` so a missed run (e.g., server was rebooted) executes on next start rather than being silently skipped.

Host security patching is handled by unattended-upgrades, configured to install security updates automatically and reboot during a configurable maintenance window (default 04:00).

`doctor` verifies all timers are active and enabled as part of its host health check.

---

## System Container

The `boxmunge-system` container encapsulates risky tooling:

- `age` — backup encryption/decryption
- `rclone` — off-box backup sync

This provides blast-radius containment — a compromised tool binary can't touch the host filesystem beyond its bind mounts. The container runs read-only, with no capabilities and a non-root user.

If the system container is not running, boxmunge falls back to host-level tool execution (for development and testing).

## Platform Validation

- `self-test` — deploys a canary project, exercises backup/restore, tears down. Proves the pipeline works.
- `health` — non-destructive audit of Docker, Caddy, containers, permissions, config drift, hardening state, and recent errors.
- `upgrade` — stash current state, migrate manifests, regenerate configs, restart, self-test, health check.

---

## MCP Server

boxmunge exposes its full command set via the Model Context Protocol (MCP) over SSH stdio transport. AI agents connect by running `mcp-serve` via SSH and speak the MCP protocol over stdin/stdout.

- One server process per SSH connection (no shared state)
- Same permissions as the restricted shell — MCP can only do what the CLI can do
- Structured JSON responses with success/exit_code/data/messages
- No additional network ports or attack surface
