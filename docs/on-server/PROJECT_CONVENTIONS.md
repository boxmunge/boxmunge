# boxmunge Project Conventions

This document defines the contract a project must fulfil to work with boxmunge. Every project hosted on a boxmunge server must conform to these conventions. boxmunge uses these conventions to deploy, proxy, monitor, back up, and restore projects without per-project configuration in the framework itself.

---

## Project Directory Layout

Each project lives at `/opt/boxmunge/projects/<project-name>/`. The directory structure is:

```
/opt/boxmunge/projects/<project-name>/
  manifest.yml                 # Declares what boxmunge needs to know
  compose.yml                  # Project-authored Docker Compose file
  compose.boxmunge.yml         # Auto-generated overlay (do not edit)
  project.env                  # Non-secret config (ships with bundle)
  secrets.env                  # CLI-managed secrets (boxmunge secrets)
  caddy.override.conf          # Optional: operator-placed Caddy config override
  boxmunge-scripts/
    smoke.sh                   # Health check (strongly recommended; 755)
    backup.sh                  # Backup to stdout (required if backup.type != none)
    restore.sh                 # Restore from stdin (required if backup.type != none)
  backups/                     # Managed by boxmunge
  data/                        # Persistent volumes (managed by project)
  repo/                        # Git clone (source: git projects only)
```

### What a bundle may contain

A bundle carries the project's code and configuration: `manifest.yml`, `compose.yml`, `project.env`,
`boxmunge-scripts/`, build contexts, and anything else the project needs.

Each bundle deploy makes the project's code exactly the bundle: a file or directory the previous
release had but the new bundle does not is removed (it stays in the previous-release copy that
`rollback` restores). So anything the project needs on the server, including `project.env`, must
ship in every bundle. Server-owned entries (below), data directories (any directory a release has
bind-mounted read-write, see below), and `-staging` copies of data directories are never
touched by a deploy (`unstage` removes the copies of directories production no longer mounts).

Some entries belong to the server, and a bundle that carries any of them is refused before anything
on the server changes (`ERROR:` naming each entry, exit 1):

| Entry | Why the server owns it |
|---|---|
| `secrets.env` | Secrets are managed on the server with `secrets set` |
| `security/` | CVE suppressions and their audit history, managed with `security suppress` / `unsuppress` |
| `data/` | The project's live data |
| `backups/` | Encrypted snapshots |
| `caddy.override.conf` | Used verbatim as the project's Caddy config, so only an operator places it, on the server |
| `repo/` | The clone of a git-sourced project |
| `.releases/`, `compose.boxmunge*.yml`, `compose.staging-base.yml` | Written by boxmunge itself |
| any top-level `<name>-staging` (`foo-staging/`, `app.db-staging`) | Reserved for staging's copies of the project's entries: staging's copy of `./foo` is `foo-staging`. Rename it |

The archive itself must hold exactly one top-level directory (the project), and only regular files,
directories and links. A link must resolve inside the project directory: a bundle with an absolute
link, a link that climbs out of the project (also through a chain of other links), a link with `..`
anywhere but at the start of its target (`sub/../x`), or a device or FIFO entry is refused with an
`ERROR:` naming the entry. Links are installed as links and are never followed.

An empty `data/`, `backups/` or `security/` directory (or one holding only empty `.gitkeep` / `.keep`
files) carries nothing; it is ignored with a `NOTE`.

**Bind-mounted directories.** A project directory that `compose.yml` bind-mounts **read-write** is a
data directory: `./uploads:/srv/uploads`, a long-syntax `type: bind` mount without
`read_only: true`, or an absolute source inside the project directory. A deploy never removes a data
directory or copies it into the previous release, and a bundle that ships content for one is
refused, because boxmunge cannot tell seed data from code that was mounted without `:ro`. Ship at
most an empty placeholder for it. A directory bind-mounted **read-only** (`:ro`, or
`read_only: true`) is code or config: it ships in the bundle and is updated on every deploy like any
other file. If boxmunge cannot read the live `compose.yml` well enough to tell which directories
hold data, the deploy is refused before anything changes.

Once a directory has been a data directory it stays one, even after a later release drops the
mount (the same holds for a bind-mounted file): boxmunge records it in
`.releases/data-dirs.json`, and no deploy, stage or rollback removes, overwrites or copies it. A
deploy whose release no longer mounts it prints a `WARNING` naming it and logs one. A bundle that
ships content under that name is refused while the server's copy holds data. Deleting retired data
is a deliberate step: when no release in use or kept for rollback needs it, an operator removes it
on the server (`rm -rf /opt/boxmunge/projects/<project>/uploads`), and the next deploy forgets it.
An empty data directory nothing mounts is forgotten too. If `data-dirs.json` is unreadable or has an
unknown `version`, deploys are refused until it is restored.

A project deployed before boxmunge kept this record starts it on its next deploy, stage, promote or
rollback, also from the compose files of the releases kept in `.releases/` (a mount the live release
already dropped may survive only there). A directory the live release only reads (mounted read-only,
nothing shipped for it but an empty placeholder) stays data. One the live `compose.yml` mounts
read-only and the new bundle ships content for becomes code, but its old contents may be an older
release's data, so the deploy first moves them to `.releases/retained/<dir>-<UTC time>/`, prints a
`WARNING` with the path and logs it; delete that copy with `rm -rf` once nothing needs it. Deploys
never touch `.releases/retained/`. If a deploy is refused because a kept release once mounted a
directory read-write that is code now, write `data-dirs.json` yourself listing only the directories
that really hold data (`{"version": 1, "data_dirs": ["uploads"]}`, or an empty list) and deploy again.

---

## Manifest Format

`manifest.yml` is the project's declaration to boxmunge. All fields shown below are supported; comments indicate which are required and what values are valid.

```yaml
# REQUIRED. Unique identifier for this project (ULID).
# Generated automatically by `boxmunge bundle` if missing.
id: 01JQXYZ1234567890ABCDEF

# REQUIRED. Must match the project's directory name exactly.
project: myapp

# REQUIRED. How this project is sourced. Valid values: bundle, git.
source: bundle

# Git repo URL. Required if source: git. Ignored for source: bundle.
repo: https://github.com/example/myapp.git

# Branch, tag, or full 40-character commit SHA to deploy. Only relevant for
# source: git. An abbreviated SHA, or a name that is both a branch and a tag,
# is refused.
ref: main

# REQUIRED. One or more hostnames this project serves.
# boxmunge generates Caddy config for each host.
hosts:
  - myapp.example.com
  - www.myapp.example.com

# Optional. Required when any entry in `hosts` is a wildcard (e.g. *.example.com).
# Wildcards are rejected by default because, on a single Caddy instance,
# one project's wildcard can capture traffic intended for adjacent projects.
# boxmunge runs single-tenant and treats this as the operator's call — but
# you must opt in explicitly so it never happens by accident.
#
# allow_wildcard_hosts: true
# hosts:
#   - "*.example.com"

# REQUIRED. One or more services. Each key is the Docker Compose service name.
services:
  frontend:
    # Type of service. Valid values: web, worker, cron.
    # "web" services are proxied by Caddy. Others are not.
    type: web

    # REQUIRED for type:web. The container port Caddy proxies to.
    port: 3000

    # REQUIRED for type:web. At least one route required.
    # Routes are dicts with a `path` key. `/` catches every request no other
    # route matches. Any other path is an exact match unless it ends in `*`:
    # `/api/*` routes everything under /api/, while `/api/` routes only the
    # literal path /api/.
    routes:
      - path: /

    # If true, excluded from the Caddy proxy (internal service only).
    # Defaults to false.
    internal: false

    # Optional. Path Caddy uses for active health checks.
    health: /healthz

    # Optional. Smoke test script (exec'd inside this container).
    # localhost:PORT works naturally. The script must be in boxmunge-scripts/.
    smoke: boxmunge-scripts/smoke.sh

    # Optional. Resource limits for this service.
    limits:
      memory: 512m
      cpus: "1.0"

  backend:
    type: web
    port: 8000
    routes:
      - path: /api/*
      - path: /admin/*
    internal: false
    health: /api/health/
    limits:
      memory: 1g
      cpus: "2.0"

  worker:
    # Workers are not proxied; no port or routes needed.
    type: worker
    limits:
      memory: 256m

# Backup configuration.
backup:
  # Valid values: none, postgres, mysql, files, custom.
  type: postgres

  # REQUIRED if type != none. Command run inside the container via `sh -c`.
  # These execute as arbitrary shell inside the target container (not on the host).
  # The manifest author controls what runs here — treat these like Dockerfile RUN commands.
  dump_command: "pg_dump -U $POSTGRES_USER $POSTGRES_DB"

  # REQUIRED if type != none. Command run inside the container via `sh -c`.
  restore_command: "psql -U $POSTGRES_USER $POSTGRES_DB"

  # Number of nightly backups to keep (whole number, at least 1). Defaults to 7.
  # Pre-deploy, pre-update and manual snapshots have their own counts
  # (see OPERATIONS.md, "Snapshot kinds and retention").
  retention: 7

# Deploy behaviour.
deploy:
  # Command run on the host, in the project directory, before containers are
  # restarted; a non-zero exit stops the deploy. It is split into words but run
  # without a shell: `&&`, pipes, redirects and `$VAR` are passed to the program
  # as plain arguments, so put more than one step in a script (mode 0755).
  # Builds (npm ci, asset compilation) belong in the image's Dockerfile.
  pre_deploy: "boxmunge-scripts/pre-deploy.sh"

  # If true, boxmunge takes a backup before deploying.
  snapshot_before_deploy: true
```

---

## Manifest Validation Rules

boxmunge validates `manifest.yml` on every deploy and rejects invalid manifests with a clear error. The rules are:

1. **`schema_version`**, when present, must be an unquoted integer from 1 to the newest version this boxmunge supports (currently 3). Absent means 1. An older schema is migrated to the current one when boxmunge reads the manifest; an upgrade also rewrites a bundle project's file, but never a git project's, which you update in the repository.
2. **`id` is required** and must be a valid ULID. Generated automatically by `boxmunge bundle` if missing from the source manifest.
3. **`project` is required** and must exactly match the project's directory name. A mismatch is an error. Project names are lowercase letters, digits, and hyphens (1-63 characters, starting with a letter or digit). Names ending in `-staging` are reserved, because boxmunge runs a project's staging copy as `<project>-staging`; `caddy` and `system` are reserved for the platform's own containers. A project created under such a name before it was reserved cannot be managed; fleet commands (`check-all`, `health`, `status`, container updates, upgrades) report it as an error and carry on with the other projects. Recreate it under another name.
4. **`source` is required** and must be `bundle` or `git`.
5. **`repo` is required if `source: git`**. The `ref` field defaults to `main` if omitted.
6. **`hosts` is required** and must contain at least one hostname. Wildcard hosts (e.g. `*.example.com`) are rejected unless the manifest top level sets `allow_wildcard_hosts: true` — see SECURITY.md for the trade-off.
7. **Each `web` service must have `port`** and **at least one entry in `routes`**, unless it sets `internal: true` (a service Caddy does not route to, declared to give it a read-only root filesystem and `writable:` paths), which may omit both. `internal` must be `true` or `false`. Routes must be dicts with a `path` key. Both values are written into the Caddy config, so they are checked strictly: `port` is an unquoted integer from 1 to 65535, and `path` starts with `/` and contains only letters, digits, `.`, `_`, `~`, `-`, and `/`, with an optional trailing `*` (`/`, `/api/*`, `/static*`). Spaces, braces, quotes, and wildcards in the middle of a path are rejected. `/` is the catch-all; every other path matches exactly unless it ends in `*`, so a path ending in `/` without `*` (such as `/api/`) draws a warning: it would not route `/api/health`.
8. **`limits`** fields are optional per service. `limits.memory` accepts Docker memory format (e.g., `256m`, `1g`). `limits.cpus` accepts a numeric string (e.g., `"0.5"`, `"2.0"`).
9. **If `backup.type` is not `none`**, both `dump_command` and `restore_command` are mandatory. A backup you cannot restore is not a backup.
10. **Per-service `smoke` is strongly recommended.** Each service can declare a `smoke: boxmunge-scripts/smoke.sh` field. The script is exec'd inside the running container, so `localhost:PORT` naturally works. boxmunge warns if no services have a smoke test.
11. **`deploy` must be a mapping, and `deploy.pre_deploy`, when set, a string** that splits into words the way a shell would (balanced quotes). It runs without a shell, so `&&`, pipes and redirects belong in a script that `pre_deploy` names.

---

## `security:` (optional)

Per-project / per-service container hardening. Absence of the block applies
the `default` profile silently — most projects need nothing here.

### Project-level fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `profile` | string | `default` | One of `default`, `off`. (`strict`, `paranoid` reserved.) |
| `reason` | string | — | **Required when `profile: off`.** Non-empty. Reproduced in deploy warnings. |
| `no_new_privileges` | bool | `true` | Set `false` to disable. |
| `init` | bool | `true` | Set `false` to disable Tini. |
| `pids_limit` | int | `512` | Set `0` to disable. |
| `cap_drop` | list[str] | dangerous-cap list | If specified, REPLACES the default list. |
| `published_ports` | list | — | Project level only. Opt-in host-published ports, each `{service, port, reason}` plus optional `host_port`, `protocol`, `host_ip` (default `127.0.0.1`). See SECURITY.md, "Published ports". |
| `cap_add` | list[str] | `[]` | Capabilities to keep; subtracted from `cap_drop`. Canonical names only (`NET_RAW`). The denylist in SECURITY.md (`SYS_ADMIN`, `SYS_MODULE`, `ALL`, ...) is rejected. |
| `user` | string | — | Per service only, or project-wide as a default. Who the service runs as: `root`, `image` (the image's own user), or a quoted `"<uid>:<gid>"` (each 1..65535). `root` and `image` **require `reason`**. See "Who a service runs as". |

### Per-service `security:`

Same fields as above. Inherits project-level values for any field omitted. A service-level `profile` overrides the project-level `profile`.

### Examples

Most common — keep default, tweak one thing:

```yaml
security:
  cap_add: [NET_RAW]
```

Per-service override:

```yaml
services:
  worker:
    security:
      pids_limit: 2048
```

Last-resort opt-out (REQUIRES `reason`):

```yaml
services:
  honeypot:
    security:
      profile: off
      reason: "intentional honeypot, see issue #42"
```

### Who a service runs as

Deploy, stage and promote build the release's images, pull the missing ones, and decide each
service's user from them; restarts, upgrades and container-update reuse that decision until the
next deploy (`boxmunge security <project>` shows it). In order:

1. compose.yml `user:` wins (the overlay adds nothing);
2. else `security.user` (the service's own block, else the project's);
3. else the image's own non-root `USER`;
4. else, under `profile: off`, the image's own user, whatever it is;
5. else, for a `build:` service, **10001:10001** (its tmpfs mounts are given to that uid);
6. else the deploy is **refused**, printing the manifest.yml lines to add.

A registry image whose `USER` is empty or root (postgres, mysql, mariadb, redis, nginx, node,
python, caddy all are) needs a declaration. For a service only compose.yml defines, add an entry
that holds nothing but its `security` block (`user`, and `reason` when it is root or image), with no
`port`, `routes` or `internal: true`: it declares who the service runs as and changes nothing else
(no read-only root filesystem, env files or proxy network). A `security` block needs
`schema_version: 2` or later.

| Image family | Add under `services.<svc>` |
|---|---|
| postgres | `security: {user: image, reason: "postgres entrypoint drops to postgres"}` |
| mysql, mariadb | `security: {user: image, reason: "entrypoint initialises as root, drops to mysql"}` |
| redis | `security: {user: "999:1000"}` for `redis:*-alpine`, `"999:999"` for the Debian tags |
| nginx | `security: {user: image, reason: "master runs as root, workers as nginx"}` |
| node (official) | `security: {user: "1000:1000"}` |
| python (run directly) | a small Dockerfile with `USER`, or `security: {user: image, reason: "..."}` |
| caddy (as a project) | `security: {user: image, reason: "binds and writes /data as root"}` |

The table is guidance only; boxmunge never uses it to decide. `boxmunge doctor` lists every
deployed service whose next deploy will be refused this way. Further refusals, each saying what
to change: a numeric non-root service whose image owns a volume's mount path as another uid (fix
it in the Dockerfile: `RUN chown <uid>:<gid> <path>`; a path the image lacks is given to the user
once); a service whose user changes while it keeps data the old user owns (run
`boxmunge data chown <project> <service> <uid>:<gid>` first: it stops the service, gives its
read-write binds and volumes to that user, and leaves it stopped for the deploy); a release that
would replace a non-empty anonymous volume with an empty named one (`data adopt` first, see
OPERATIONS.md). Data in an anonymous volume warns at every deploy until it is adopted, and is refused on a
box whose Docker daemon remaps user namespaces. A user change is checked even with no earlier
user to compare: a numeric user over existing data another user owns is refused the same way. A
`build:` service that fails smoke on the 10001 default gets a hint: it may need a passwd entry
(add `USER` to the Dockerfile) or a `security.user`. container-update does not recreate a
service that runs as its image's user when a new image changes that `USER`; it alerts, and the
next deploy decides.

---

## Compose File Conventions

`compose.yml` is written and maintained by the project. It must:

- Define all services listed in the manifest.
- Use `restart: unless-stopped` on all long-running services.
- **Not** include boxmunge networking (`boxmunge-proxy`). boxmunge injects that via the generated overlay.
- **Not** publish ports (`ports:`). Caddy is the only ingress; declare an unavoidable host port under the manifest's `security.published_ports` instead.
- **Not** set `container_name`. Compose names each container `<project>-<service>-<n>`; services reach each other by service name.
- Keep bind mounts, `secrets`/`configs` files, and build contexts inside the project directory, and declare only the project's own networks and volumes (aliases on those are fine). The full list is in SECURITY.md, "What `compose.yml` may not do".
- Mount the project directory, and anything boxmunge reads from it (`compose.yml`, `manifest.yml`, `.env`, `.releases/`, ...), read-only only; give the container a data subdirectory such as `./data` to write. Do not nest one bind mount inside another read-write one.
- **Not** set a top-level `name:`. boxmunge runs every compose command with `-p <project>` (`-p <project>-staging` for staging), and rejects a `name:` line so a compose file can never address another project's containers or volumes.

boxmunge generates `compose.boxmunge.yml` alongside `compose.yml`. **Do not edit this file** -- it is regenerated on every deploy.

### What the Generated Overlay Contains

`compose.boxmunge.yml` adds:

- **Proxy network** -- the `boxmunge-proxy` external network to every non-internal `web` service, with project-scoped network aliases (e.g., `myapp-frontend`, `myapp-backend`)
- **Environment files** -- `env_file` entries for `project.env` and `secrets.env`, injecting both non-secret config and CLI-managed secrets into containers
- **Resource limits** -- `deploy.resources.limits` for services declaring `limits` in the manifest, enforcing memory and CPU constraints
- **Container hardening** -- under the `default` security profile (the silent floor): `security_opt: ["no-new-privileges:true"]`, `init: true`, `pids_limit: 512`, a curated `cap_drop` list, and (v0.8) `read_only: true` and `tmpfs: ['/tmp']`. Services the manifest does not list (databases, caches, sidecars) get the same flags, resolved against the project-level `security:` block, **except** `read_only` and the `/tmp` tmpfs. Every deploy, stage, and validate warns about each undeclared service; a future release will make read-only the default for them too. To give one a read-only root filesystem now, declare it under `services:` with `internal: true` (no `port` or `routes` needed) and a `writable:` block, as shown in SECURITY.md ("Services that are not in the manifest").

Services with `internal: true` are excluded from the proxy network.

### v0.8 read-only rootfs default

The default profile applies `read_only: true` and `tmpfs: ['/tmp']` to every service declared in the manifest (services only in `compose.yml` do not get them yet; see the overlay section above). Pre-v0.8 the CVE policy penalised missing `read_only` without enforcing it; v0.8 closed that asymmetry.

If a service legitimately needs writable rootfs, declare `read_only: false` in the project's `compose.yml` for that service. Doing so:

- Tells the overlay to omit its own `read_only` (your literal value wins via Compose merge — no merge conflict)
- Incurs a +1 CVE hardening penalty (see CVE_POLICY.md)
- **(v0.9)** Emits a `[WARNING]` on every deploy naming the service — no more silent override

---

### v0.9 writable: abstraction (schema v3)

Services that need writable paths beyond `/tmp` declare them in the manifest under `services.<name>.writable`. The technical translation into compose tmpfs/volumes happens inside boxmunge — operators describe *what their app needs to write to*, not *how docker should mount it*.

Every service is in exactly one of three states:

| State | Manifest shape | Behaviour |
|---|---|---|
| **default** | no `writable:` block | Read-only rootfs + tmpfs:/tmp baseline only. Compose-side `tmpfs:` or named-volumes for this service → deploy error. |
| **manifest-managed** | `writable.ephemeral` and/or `writable.persistent` | boxmunge emits the compose tmpfs/volumes. Compose-side `tmpfs:` or named-volumes for this service → deploy error. |
| **externally-managed** | `writable.external: true` | boxmunge emits **no** tmpfs (not even /tmp) and **no** volumes. Compose-side declarations accepted. `[INFO]` warning every deploy. Mutually exclusive with `ephemeral`/`persistent`. |

`read_only: true` still applies in all three states. To opt out of read-only rootfs entirely, set `read_only: false` in compose.yml (orthogonal to `writable:`, separate penalty).

#### Schema

```yaml
schema_version: 3
services:
  web:
    writable:
      ephemeral:                  # tmpfs paths, wiped on restart
        - /var/cache/nginx
        - /var/run
        # /tmp is implicit (already in the baseline)
      persistent:                 # named docker volumes (survive restart)
        - name: dbdata            # ^[a-z0-9][a-z0-9-]{0,30}$, unique within service
          mount: /app/data        # absolute path, no trailing slash
```

For services with delegated writability:

```yaml
services:
  legacy:
    writable:
      external: true              # boxmunge stays out of tmpfs/volumes for this service
```

#### Validation rules

- All paths must be absolute and canonical (no `.` or `..` segments, repeated `/`, or trailing slash: write `/app/data`, not `/app/./data/`), max 256 chars, with no `:`, `,` or control characters (Compose would read `:` and `,` as mount options). The error names the canonical spelling to use.
- `ephemeral` entries: list of strings, no duplicates within the list.
- `persistent` entries: `{name, mount}` mappings. **Names must be unique project-wide** (across all services), not just within one service — the overlay declares each volume as `<project>_<name>`, so two services declaring the same `name` would alias to the same physical volume. Docker Compose then prefixes the compose project name, so the Docker volume on the host is `<project>_<project>_<name>` (staging's is `<project>-staging_<project>_<name>`). Mounts unique within the service.
- A path cannot appear in both `ephemeral` and `persistent` for the same service.
- A `persistent` mount cannot be nested under any `ephemeral` path (tmpfs would shadow the volume at runtime).
- Reserved roots (`/`, `/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`, `/proc`, `/sys`, `/dev`) cannot be used as persistent mounts.
- `/tmp`, `/var/run`, `/run` declared as `persistent` → error ("did you mean ephemeral?").
- `external: true` is mutually exclusive with `ephemeral` and `persistent`.
- `external: false` is rejected — omit the field instead.

#### Worked examples

A simple static-asset service with no writability:

```yaml
services:
  web:
    port: 80
    routes: [{path: /}]
    # No writable: block — read-only rootfs + /tmp tmpfs baseline.
```

An nginx frontend needing cache + pid file:

```yaml
services:
  frontend:
    port: 80
    routes: [{path: /}]
    writable:
      ephemeral:
        - /var/cache/nginx
        - /var/run
```

A database service with persistent storage:

```yaml
services:
  web:
    port: 8000
    routes: [{path: /}]
    writable:
      persistent:
        - name: dbdata
          mount: /app/data
```

A legacy service the operator wants to keep managing in compose.yml directly:

```yaml
services:
  legacy:
    port: 9000
    routes: [{path: /legacy}]
    writable:
      external: true
```

#### Diagnostics

When a container hits a "Read-only file system" error after deploy, boxmunge surfaces a hint pointing the operator at the relevant `writable:` block:

- **Deploy-time**: 8s post-`compose up` scan of each service's container logs. Matches surface as a `[HINT]` block in deploy output, with the offending path extracted.
- **Smoke-failure path**: when a smoke test fails, the failure message is enriched with the same hint if recent logs contain a read-only-fs error.
- **`boxmunge logs <project>`**: non-follow mode appends a one-block writable-hint postscript when the captured log buffer contains read-only-fs errors.

For externally-managed services, hints point at compose.yml instead of the manifest.

---

## boxmunge-scripts/ Contract

The `boxmunge-scripts/` directory is the project's side of the integration. boxmunge calls these scripts at defined lifecycle points. All scripts must be executable (`0755`).

| Script | When called | Required? |
|---|---|---|
| `smoke.sh` | After every deploy, and periodically by the health monitor | Strongly recommended |
| `backup.sh` | On scheduled backup runs and `snapshot_before_deploy` | Required if `backup.type != none` |
| `restore.sh` | During a restore operation | Required if `backup.type != none` |

---

## Smoke Test Contract

Smoke tests are **per-service**. Each service that declares a `smoke` field in the manifest gets its script exec'd inside the running container via `docker exec`. This means:

- **`localhost:PORT` works naturally** — the script runs in the same network namespace as the service.
- **The script must only use tools available inside the container.** boxmunge does not install anything. If your smoke script uses `curl`, your Dockerfile must install `curl`. If the container is Python-based, use Python's `urllib` instead. Alpine images have `wget`. Plan accordingly.
- Scripts live in `boxmunge-scripts/` on the host and are bind-mounted into the container at `/boxmunge-scripts/`.
- Scripts are invoked via `sh` with the **service name as `$1`** (e.g., `web`, `api`). This lets a shared smoke script branch on which service it is testing.
- Use `#!/bin/sh` shebangs (not `#!/bin/bash`) unless you know bash is in the container.

### Exit Codes

| Exit code | Meaning | boxmunge action |
|---|---|---|
| `0` | Healthy. Also clears any prior failure state. | None; deployment proceeds or monitor resets. |
| `1` | Warning or degraded. | Alert after configurable threshold of consecutive failures. |
| `2` | Critical. | Alert immediately; stop all project containers; enter `critical_stopped` state. |

### Stderr Protocol

boxmunge reads one message from stderr and uses it in alerts and logs:

- **One non-blank line** on stderr: used verbatim as the message.
- **Multiple non-blank lines** on stderr: collapsed to `"Manual failure analysis required"`.
- **No output** on stderr: a generic message is used (`"Smoke test failed with no output"`).

For exit code `1`, boxmunge performs **message-aware deduplication**: if the same message repeats across consecutive checks, only the first occurrence triggers an alert (until the message changes or the check recovers).

For exit code `2` (critical), boxmunge stops all project containers and marks the project `critical_stopped`. The project will not restart until an explicit deploy.

### Example Smoke Scripts

**Python container** (no curl needed):

```sh
#!/bin/sh
python3 -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('http://localhost:8080/healthz', timeout=5)
    sys.exit(0 if r.status == 200 else 1)
except Exception as e:
    print(f'Health check failed: {e}', file=sys.stderr)
    sys.exit(1)
"
```

**Alpine-based container** (wget available):

```sh
#!/bin/sh
wget -qO/dev/null --timeout=5 http://localhost:3000/healthz 2>/dev/null
```

**Container with curl installed**:

```sh
#!/bin/sh
curl -sf --max-time 5 http://localhost:8000/healthz > /dev/null
```

---

## Environment File Conventions

boxmunge uses two environment files per project, both injected into containers via the generated compose overlay:

### secrets.env (CLI-managed)

Runtime secrets managed exclusively via `secrets`:

```
secrets set myapp DATABASE_URL=postgres://user:pass@db:5432/myapp
secrets set myapp SECRET_KEY=supersecretvalue
```

Do not edit `secrets.env` manually. The CLI handles file creation, permissions, and format. Secrets set via the CLI are available to containers on the next deploy, byte for byte as set: `$`, `#`, quotes and spaces are not interpreted.

### project.env (ships with bundle)

Non-secret configuration that ships as part of the project bundle:

```
ALLOWED_HOSTS=myapp.example.com
LOG_LEVEL=info
NODE_ENV=production
```

`project.env` is part of the project source and is replaced on each bundle deploy. It should not contain credentials.

### `${VAR}` in compose.yml

Compose fills `${VAR}` in `compose.yml` only from the project's `.env` file. boxmunge runs Compose with a fixed environment (`PATH` and `LANG` only), so shell variables such as `${HOME}` or `${USER}`, and anything set in the deploy session, are unset and resolve to an empty string (or the `${VAR:-default}`). This gives the same result for a deploy and for a root timer. Put any value the compose file needs in `.env`.

---

## CVE Suppressions Convention

If the project has any operator-reviewed CVE suppressions, they live in:

```
<project>/security/suppressions.yml
```

The file is server-side state, next to its history file
(`suppressions.history.yml`). Every suppression carries its `cve`,
`until`, `reason`, `reviewed_by`, and `added` fields. Schema and field
requirements are defined in CVE_POLICY.md (`agent-help cve`). A bundle
that carries a `security/` directory is refused, so a redeploy can never
replace the server's suppressions or erase their history.

**Do not edit `suppressions.yml` manually.** It is managed exclusively
by:

```
boxmunge security suppress <CVE> --project <name> --until <DATE> --reason <text>
boxmunge security unsuppress <CVE> --project <name>
```

The CLI handles file creation, schema validation, atomic writes, and
emits the corresponding `cve-suppress` audit log entry. Hand-edits
bypass the audit trail and risk breaking the schema.

---

## Caddy Override

`caddy.override.conf` is an escape hatch for projects with routing requirements that boxmunge's generated Caddy config cannot express. If this file is present, boxmunge uses it **verbatim** in place of the generated Caddy configuration for the project's hosts.

Because it is raw proxy configuration, it is operator-only: an operator places it in `/opt/boxmunge/projects/<project>/` on the server. A bundle that carries `caddy.override.conf` is refused, and deploys and rollbacks never remove or replace it.

Use this only when necessary. Projects using `caddy.override.conf`:

- Take full responsibility for correct TLS, routing, and upstream configuration.
- Will not benefit from future improvements to boxmunge's Caddy generation.
- Must ensure their override remains valid Caddyfile syntax -- boxmunge will refuse to reload Caddy with an invalid config, put back the site config Caddy last accepted, and fail the operation.

When in doubt, request a manifest feature rather than reaching for the override.
