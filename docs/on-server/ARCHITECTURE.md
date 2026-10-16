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
      caddy.override.conf     # optional: verbatim Caddy config escape hatch (operator-placed)
      boxmunge-scripts/       # project's integration scripts
        smoke.sh
        backup.sh
        restore.sh
        migrate.sh
      backups/                # encrypted local backup archives
      data/                   # persistent volume mounts
      repo/                   # git clone (source: git projects only)
      .releases/              # release workspace (managed by boxmunge)
        incoming/             # a bundle being validated (transient)
        previous/             # code of the release the last deploy replaced (rollback target)
        previous.json         # its bundle name and pre-deploy data snapshot
        install.json          # the open install transaction (only while an install runs)
        previous.superseded/  # the rollback target an open install replaced, until it closes
        prestage/             # production code displaced by `stage`, until promote/unstage
        live-mounts/          # production's copies of the release code it bind-mounts
        live-scripts/         # production's copy of boxmunge-scripts/ (smoke checks)
        live.json             # bundle name of the installed release
  inbox/                      # uploaded bundles awaiting deployment
  state/                      # operational state (deploy:deploy 755)
    health/                   # per-project health state JSON
    deploy/                   # per-project deploy state JSON
    staging/                  # per-project staging state
  docs/                       # on-server documentation (root:root 755)
  logs/                       # boxmunge operational logs (deploy:deploy 755)
    boxmunge.log              # today's entries (UTC); writers rotate it under a lock
    boxmunge.log.YYYY-MM-DD   # one archive per earlier day, 90 kept
    .boxmunge.log.lock        # rotation lock (0660, deploy group only)
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

When a project is staged, its containers run alongside production as compose project `<project>-staging`, on its own networks with its own volumes, container names, image tags and `-staging` data directories; `stage` proves with `docker compose config` that the two environments share none of them before starting anything. Caddy routes `staging.<hostname>` to the staged containers. Promoting tears down staging and replaces production. Unstaging tears down staging without affecting production.

### Config Generation

`deploy` (and `stage`) reads the `services` block in `manifest.yml` and generates two files:

1. Caddy site config -- reverse proxy rules, ordered by route specificity
2. `compose.boxmunge.yml` -- Docker Compose overlay that attaches routable services to `boxmunge-proxy` with their aliases, injects env_files, and applies resource limits

The project's own `compose.yml` does not need to reference boxmunge networking at all. The overlay is the platform's concern.

If a project contains `caddy.override.conf`, boxmunge uses it verbatim instead of generating config. A notice is logged when this escape hatch is active. Only an operator places it, directly on the server: a bundle that carries one is refused, and deploys never remove it.

Caddy validates the whole configuration before every reload. If it rejects the new config, boxmunge puts back each site file (production or staging) written since Caddy last accepted a config (kept in `caddy/.site-journal/`) and the operation fails with an `ERROR` naming the rejected site, so one bad site file cannot stop Caddy reloading or restarting for every other project. A `prod-deploy` that fails this way leaves the new release's containers running behind the restored previous routing: fix the site config and deploy again, or `rollback` when a previous release exists. A `stage` that fails this way is cleaned up like any failed stage. If Caddy is not running, nothing can be validated and the new files stay in place until it starts. `unstage` deletes the staging site and drops its journal entry, so a later restore never brings back routing to torn-down staging containers.

The journal is writable by `deploy`, and restoring runs as root, so its entries are not trusted. An entry may only name the site file in `caddy/sites/` that its own file name names (`<site>.conf.json` for `<site>.conf`), neither may be a symlink, and it must hold exactly what boxmunge writes. Any other entry is refused and left in place: the other entries are still restored, and the error names the refused entry. Delete it as root, then check the site files in `caddy/sites/`.

---

## Privilege Model

boxmunge uses two users with distinct access levels:

### deploy (restricted shell)

The `deploy` user runs a restricted boxmunge shell. Agents connect as `deploy`.

- Can **only** run `boxmunge` commands -- no `ls`, `cat`, `cd`, `docker`, or any other shell command
- Cannot browse the filesystem or read files directly
- Cannot run `sudo` itself. The shell's `upgrade` and `upgrade --target <version>` commands
  reach the root upgrade shim through a sudo rule that permits exactly
  `boxmunge-upgrade auto` and `boxmunge-upgrade target <version>`, nothing else
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

1. Resolve source -- locate the bundle in the inbox, or pull from the git repo
2. Unpack -- a bundle is extracted into `projects/<project>/.releases/incoming/`, not over the live project
3. Validate -- manifest schema and required fields (`id`, `source`, `project`, `hosts`, services), project identity (ULID), the user `compose.yml` against the hardening floor, and the bundle's contents against the server's data directories. For a bundle all of this runs on the unpacked copy: a rejected bundle never touches the live project files, so no later timer or restart can start it
4. Pre-deploy snapshot -- encrypted backup of the current data, taken with the outgoing release's own backup configuration (unless `--no-snapshot`)
5. Keep the outgoing release -- its code is copied to `.releases/previous/` and paired with that snapshot, for `rollback`
6. Install -- only a release that passed every check replaces the live project files
7. Pre-deploy command -- run `deploy.pre_deploy` from manifest if defined (e.g., migrations)
8. Generate configs -- write Caddy site config and compose overlay (networking, env_files, resource limits)
9. Start containers -- re-validate the installed files, check every bind source without following symlinks and record its kind (creating missing ones as directories), then `docker compose up -d` with overlay. Every later start (upgrade, container update, `recover`, `resume`, `restore`) repeats the check against that record first; see TRUST_MODEL.md, "Container Escape and Root Restarts"
10. Reload Caddy -- graceful, zero-downtime
11. Smoke test -- run `boxmunge-scripts/smoke.sh`, interpret exit code
12. Record state -- write deploy state JSON atomically
13. Log the deployment -- append to boxmunge operational log

A bundle that fails validation stays in the inbox (it is not moved to `.consumed/`) and the command exits non-zero: 3 for a compose hardening rejection, 1 otherwise. `stage` uses the same unpack-validate-install path, but keeps the production release in `.releases/prestage/` instead of step 5 and takes no snapshot.

If any step fails, the deploy stops and reports the failure. No automatic rollback -- the operator or agent decides what to do next.

Steps 5 to 9 of a bundle deploy, and every bundle rollback, run inside an install transaction (`release_txn`, `.releases/install.json`). It records the release being installed, the one it replaces, the snapshot that pairs with it, and the phase reached: `committed`, `previous_kept` (the keep moves the old rollback target to `previous.superseded/` rather than deleting it), `installed`, `hook_started` and `switching` (a rollback has `data_restored` instead of `previous_kept`). Each phase is written durably before or after the step it names, so a rerun resumes from it with the same snapshot; `prod-deploy <project> --abandon` undoes it before `hook_started`, through its own durable checkpoints so a rerun after a crash finishes it; a different deploy fixes forward and inherits the rollback pairing and what the attempts it replaced may have done (a hook that ran, containers that started), so it cannot be abandoned once data may have changed. While it is open, `compose_guard` refuses every production start except the one passing the transaction's id, so an upgrade restart or `resume` cannot start a half-installed release. The record also holds the hashes of `live.json` and `previous.json`; a mismatch none of its own steps explains marks it stale, and nothing is resumed automatically.

### Staging Flow

`stage <project>` follows the same steps but deploys to the staging environment at `staging.<hostname>`. After verification:

- `promote <project>` -- deploys the staged release to production, then tears down staging
- `unstage <project>` -- tears down staging and puts the production release's files back

The staged release is installed in the project directory (staging containers run from it); the
production release it displaces is kept in `.releases/prestage/` until promote or unstage. A stage
that fails after installing cleans up the same way unstage does. Staging state is tracked under
`state/staging/`.

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
- `state/deploy/<project>.json` -- current ref (the bundle name, e.g. `myapp-2026-10-13T101500123456`, or the git commit), deploy timestamp, pre-deploy snapshot filename, recent history
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

1. Run the dump command from the manifest, with a 10-minute limit (on overrun or interruption its processes are killed inside the container). Its output goes to a private (0600) `.dump-*` file in the project's `backups/` directory: the plaintext touches disk until step 2 finishes
2. Encrypt with age using the backup key, then remove the plaintext dump (also on any failure or timeout)
3. Write atomically to `<project>/backups/<project>-<ISO8601>-<kind>.tar.gz.age`, where kind is `nightly`, `predeploy`, `preupdate` or `manual`
4. Prune local archives of the same kind beyond that kind's retention count (see OPERATIONS.md)
5. Log the backup

Off-box sync uses `rclone copy` to push encrypted archives to the configured remote. It never deletes off-site copies, so the remote is an archive rather than a mirror of local retention. Since archives are encrypted before leaving the box, the remote is untrusted storage.

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
| `boxmunge-cve-scan.timer` | Daily at 03:00 (up to 30 min jitter) | `security scan` |
| `boxmunge-container-update.timer` | Daily at 03:00 (up to 60 min jitter) | `container-update` |
| `boxmunge-auto-update.timer` | Every 6 hours (up to 30 min jitter) | `auto-update` |

All timers use `Persistent=true` so a missed run (e.g., server was rebooted) executes on next start rather than being silently skipped.

Host security patching is handled by unattended-upgrades, configured to install security updates automatically and reboot during a configurable maintenance window (default 04:00). Because an enabled service proves nothing about updates arriving, the `auto-updates` health check and every `auto-update` run look for evidence (a recent successful `apt-get update`, a recent successful `unattended-upgrade` run, successful apt-daily runs), and `auto-update` sends a Pushover alert when it is missing.

`doctor` and the `timers` health check verify that every timer above is active.

---

## System Container

The `boxmunge-system` container encapsulates risky tooling:

- `age` — backup encryption/decryption
- `rclone` — off-box backup sync

This provides blast-radius containment — a compromised tool binary can't touch the host filesystem beyond its bind mounts. The container runs read-only, with no capabilities, as the `deploy` user's uid:gid. `install.sh` writes them to `/opt/boxmunge/system/.env` from `id -u deploy` and `id -g deploy`; boxmunge refuses to use a container running as any other uid.

Its mounts are fixed: `projects/` read-write at `/projects`, `config/backup.key` read-only at `/config/backup.key`, and `config/rclone/` read-only at `/config/rclone`. Every path boxmunge hands to age or rclone must sit under one of these mounts, or the operation fails before the tool runs.

There is no host fallback. If the system container is missing, stopped, or mounted for a different boxmunge root, backups, restores, `test-restore` and `backup-sync` fail with an error saying how to start it, and `health` reports an error.

## Per-Project Container Hardening

Beyond the platform containers above, boxmunge applies a silent hardening layer to every user service at deploy time.

The `default` profile (applied when no `security:` block is present) injects into the generated `compose.boxmunge.yml`:

- `security_opt: ["no-new-privileges:true"]` — blocks setuid / file-cap escalation inside the container
- `init: true` — Tini for signal handling and zombie reaping
- `pids_limit: 512` — kills fork bombs and exec storms
- `cap_drop` of 14 dangerous Linux capabilities not in Docker's default deny set (`NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_TIME`, `SYS_BOOT`, `MAC_ADMIN`, `MAC_OVERRIDE`, `MKNOD`, `AUDIT_WRITE`, `WAKE_ALARM`, `BLOCK_SUSPEND`, `LEASE`, `NET_RAW`)

Existing v1 manifests gain the floor automatically on next deploy — no edits required.

### Relaxation

Projects that need a specific protection eased declare a `security:` block in `manifest.yml`. Project-level applies to every service; per-service blocks override. Strongly preferred is keeping `profile: default` and tweaking the single field that needs relaxing (e.g. `cap_add: [NET_RAW]`, `pids_limit: 2048`).

A last-resort `profile: "off"` requires a non-empty `reason` and triggers repeated `[WARNING] SECURITY OFF` deploy-time output.

### compose_validate

Before configs are written, `compose_validate.py` (added in v0.5) inspects the project's user-authored `compose.yml` and rejects any keys that would defeat the hardening floor — e.g. `privileged: true`, `cap_add: [SYS_ADMIN]`, `security_opt` overrides that re-enable privilege escalation — or reach another project. It checks the resolved model from `docker compose -p <project> config` (interpolation, `.env`, `extends`, `include` applied), and the literal files for `include`/`extends`/`env_file` paths leaving the project. This runs at stage, deploy, resume, and upgrade time, so the floor cannot be silently sidestepped from the user side. The overlay generator reads the same resolved model, so services that arrive through `include:` are hardened too.

### Where it fits in the deploy flow

Between step 5 ("Generate configs") and step 6 ("Start containers") in the deploy flow above, boxmunge:

1. Resolves the effective security posture per service (profile + project overrides + service overrides + cap_add subtraction).
2. Runs `compose_validate` on the user's `compose.yml`.
3. Emits the hardening fields into `compose.boxmunge.yml` so `docker compose up -d` applies them.

See `TRUST_MODEL.md` for the threat model and `agent-help security` for the runtime introspection command.

### Writable surface abstraction (v0.9, schema v3)

The v0.8 read-only-rootfs default left operators reaching into compose syntax (`tmpfs:`, `volumes:`, named-volume top-level blocks) whenever an app needed writable paths beyond `/tmp`. v0.9 lifts that into the manifest as a `writable:` block, so operators describe *what their app writes to* rather than *how docker should mount it*.

Two new pure modules carry the logic:

- `src/boxmunge/writable.py` — schema validation, three-state classification (`default` / `manifest-managed` / `externally-managed`), translation helpers, display helpers (`describe_state`, `writable_json`).
- `src/boxmunge/writable_diagnostics.py` — read-only-fs log scanner + hint formatter + post-deploy orchestration (`run_post_deploy_diagnostics`, `enrich_failure_with_writable_hint`).

Hard cutover, no coexistence layer. Compose-side `tmpfs:` or named-volume references for a non-external service are rejected at deploy time by `compose_validate` with a three-option migration message. The boxmunge overlay generator (`compose.py:_build_service_override`) reads the manifest's `writable:` block, translates to compose tmpfs/volumes, and emits top-level named-volume declarations.

Three deploy-time visibility signals fire whenever relevant:

- `[WARNING]` per service for `read_only: false` in user compose (no more silent v0.8 override)
- `[INFO]` per service for `writable.external: true` in manifest
- `[HINT]` per service for read-only-fs errors in the first 8s of container logs after `compose up`

The 8s post-up scan runs from `commands/deploy.py` via a module-level `_sleep_fn` indirection that the test conftest replaces with a no-op to keep the unit suite fast. Smoke-failure messages are similarly enriched via `enrich_failure_with_writable_hint`. `boxmunge logs <project>` (non-follow) appends a one-block postscript when the captured buffer contains matching errors.

See `agent-help writable` and `PROJECT_CONVENTIONS.md` for the schema reference.

## Platform Validation

- `self-test` — deploys a canary project, exercises backup/restore, tears down. Proves the pipeline works.
- `health` — non-destructive audit of Docker, Caddy, containers, permissions, config drift, hardening state, and recent errors.
- `upgrade` — stash current state, migrate manifests, regenerate configs (paused and quarantined projects keep
  their maintenance page), restart, self-test, health check. `upgrade --dry-run` renders all of this in memory
  and writes nothing.
  A failed gate (config regeneration, Caddy reload, restart, self-test) fails the upgrade; it is never reported
  as a warning followed by "Upgrade complete".

## CVE Policy Module

Beyond per-container hardening, boxmunge runs a CVE policy engine that scans deployed images and quarantines projects whose findings cross a posture threshold.

- **Where it sits** — runs after every successful deploy/stage/promote/resume, and via `boxmunge-cve-scan.timer` daily at 03:00 (±30 min jitter). Lives in `src/boxmunge/cve/` (scanner, policy, quarantine, suppressions, alerting, scan_state, grace) plus the orchestrating `commands/security_*.py`.
- **Inputs** — Trivy's vulnerability DB (refreshed before each scan), the project's `manifest.yml` (`security.posture`, `dangerously_disable_quarantine`, hardening fields), and the project's `security/suppressions.yml` if present.
- **Outputs** — per-project `.cve/scan_state.json` (the durable record), quarantine actions (`compose stop` + maintenance Caddy fragment + critical Pushover alert), informational alerts for sub-threshold findings, and structured `log_operation` entries under `cve-scan` / `cve-suppress` / `cve-quarantine` components.
- **Per-project scan budget** — each project gets a 600-second wall-clock budget across its image scans. Exceeding it skips remaining images (logged at WARNING) and resumes on the next tick.

See `agent-help cve` (CVE_POLICY.md) for posture tiers, hardening penalty, suppression schema, recovery flow, and alerts.

---

## MCP Server

boxmunge exposes a subset of its command set via the Model Context Protocol (MCP) over SSH stdio transport. AI agents connect by running `mcp-serve` via SSH and speak the MCP protocol over stdin/stdout.

- One server process per SSH connection (no shared state)
- Runs as deploy, like the restricted shell. Every tool corresponds to an allowlisted shell command
- `upgrade` takes the shell's path: `sudo -n boxmunge-upgrade auto` (or `target <version>`), so it gets
  the same signature check, venv swap, probation and rollback. It never upgrades in-process
- Destructive tools `restore` and `rollback` refuse to run unless called with `confirm: true`
- Structured JSON responses with success/exit_code/data/messages. `messages` holds the command's
  stdout and stderr in order, so `ERROR:` lines reach the agent
- The protocol uses private copies of the original stdin/stdout. Inside the server, fd 0 is
  `/dev/null` and fd 1 is stderr, so nothing a tool runs (docker, git, a stray prompt) can read
  from or write into the JSON-RPC stream
- No additional network ports or attack surface
