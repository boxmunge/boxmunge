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
  caddy.override.conf          # Optional: manual Caddy config override
  boxmunge-scripts/
    smoke.sh                   # Health check (strongly recommended; 755)
    backup.sh                  # Backup to stdout (required if backup.type != none)
    restore.sh                 # Restore from stdin (required if backup.type != none)
    migrate.sh                 # Optional pre-deploy migration (755)
  backups/                     # Managed by boxmunge
  data/                        # Persistent volumes (managed by project)
  repo/                        # Git clone (source: git projects only)
```

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

# Branch, tag, or commit SHA to deploy. Only relevant for source: git.
ref: main

# REQUIRED. One or more hostnames this project serves.
# boxmunge generates Caddy config for each host.
hosts:
  - myapp.example.com
  - www.myapp.example.com

# REQUIRED. One or more services. Each key is the Docker Compose service name.
services:
  frontend:
    # Type of service. Valid values: web, worker, cron.
    # "web" services are proxied by Caddy. Others are not.
    type: web

    # REQUIRED for type:web. The container port Caddy proxies to.
    port: 3000

    # REQUIRED for type:web. At least one route required.
    # Routes are dicts with a `path` key.
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
      - path: /api/
      - path: /admin/
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

  # Number of daily backups to retain. Defaults to 7.
  retention: 7

# Deploy behaviour.
deploy:
  # Shell command(s) run before containers are restarted.
  pre_deploy: "npm ci --prefix frontend && npm run build --prefix frontend"

  # If true, boxmunge takes a backup before deploying.
  snapshot_before_deploy: true
```

---

## Manifest Validation Rules

boxmunge validates `manifest.yml` on every deploy and rejects invalid manifests with a clear error. The rules are:

1. **`id` is required** and must be a valid ULID. Generated automatically by `boxmunge bundle` if missing from the source manifest.
2. **`project` is required** and must exactly match the project's directory name. A mismatch is an error.
3. **`source` is required** and must be `bundle` or `git`.
4. **`repo` is required if `source: git`**. The `ref` field defaults to `main` if omitted.
5. **`hosts` is required** and must contain at least one hostname.
6. **Each `web` service must have `port`** and **at least one entry in `routes`**. Routes must be dicts with a `path` key.
7. **`limits`** fields are optional per service. `limits.memory` accepts Docker memory format (e.g., `256m`, `1g`). `limits.cpus` accepts a numeric string (e.g., `"0.5"`, `"2.0"`).
8. **If `backup.type` is not `none`**, both `dump_command` and `restore_command` are mandatory. A backup you cannot restore is not a backup.
9. **Per-service `smoke` is strongly recommended.** Each service can declare a `smoke: boxmunge-scripts/smoke.sh` field. The script is exec'd inside the running container, so `localhost:PORT` naturally works. boxmunge warns if no services have a smoke test.

---

## Compose File Conventions

`compose.yml` is written and maintained by the project. It must:

- Define all services listed in the manifest.
- Use `restart: unless-stopped` on all long-running services.
- **Not** include boxmunge networking (`boxmunge-proxy`). boxmunge injects that via the generated overlay.

boxmunge generates `compose.boxmunge.yml` alongside `compose.yml`. **Do not edit this file** -- it is regenerated on every deploy.

### What the Generated Overlay Contains

`compose.boxmunge.yml` adds:

- **Proxy network** -- the `boxmunge-proxy` external network to every non-internal `web` service, with project-scoped network aliases (e.g., `myapp-frontend`, `myapp-backend`)
- **Environment files** -- `env_file` entries for `project.env` and `secrets.env`, injecting both non-secret config and CLI-managed secrets into containers
- **Resource limits** -- `deploy.resources.limits` for services declaring `limits` in the manifest, enforcing memory and CPU constraints

Services with `internal: true` are excluded from the proxy network.

---

## boxmunge-scripts/ Contract

The `boxmunge-scripts/` directory is the project's side of the integration. boxmunge calls these scripts at defined lifecycle points. All scripts must be executable (`0755`).

| Script | When called | Required? |
|---|---|---|
| `smoke.sh` | After every deploy, and periodically by the health monitor | Strongly recommended |
| `backup.sh` | On scheduled backup runs and `snapshot_before_deploy` | Required if `backup.type != none` |
| `restore.sh` | During a restore operation | Required if `backup.type != none` |
| `migrate.sh` | During deploy, before containers restart, after `pre_deploy` | Optional |

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
secrets set myapp DATABASE_URL postgres://user:pass@db:5432/myapp
secrets set myapp SECRET_KEY supersecretvalue
```

Do not edit `secrets.env` manually. The CLI handles file creation, permissions, and format. Secrets set via the CLI are available to containers on the next deploy.

### project.env (ships with bundle)

Non-secret configuration that ships as part of the project bundle:

```
ALLOWED_HOSTS=myapp.example.com
LOG_LEVEL=info
NODE_ENV=production
```

`project.env` is part of the project source and is replaced on each bundle deploy. It should not contain credentials.

---

## Caddy Override

`caddy.override.conf` is an escape hatch for projects with routing requirements that boxmunge's generated Caddy config cannot express. If this file is present, boxmunge uses it **verbatim** in place of the generated Caddy configuration for the project's hosts.

Use this only when necessary. Projects using `caddy.override.conf`:

- Take full responsibility for correct TLS, routing, and upstream configuration.
- Will not benefit from future improvements to boxmunge's Caddy generation.
- Must ensure their override remains valid Caddyfile syntax -- boxmunge will refuse to reload Caddy with an invalid config and will alert.

When in doubt, request a manifest feature rather than reaching for the override.
