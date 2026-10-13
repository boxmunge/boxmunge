# boxmunge Operations Guide

Step-by-step instructions for common tasks on a boxmunge-managed server.

All operations use boxmunge commands. For detailed help on any command, run `help <command>`. It
prints that command's usage and never runs the command.

---

## Deploying a New Project (Bundle)

The standard workflow for deploying a project from a bundle.

1. Build a bundle locally (generates a ULID if `id` is missing from the manifest):

   ```
   boxmunge bundle ./myapp
   ```

2. Upload the bundle to the server:

   ```
   scp -O -P 922 myapp.tar.gz deploy@<host>:
   ```

   Bundles land in the inbox automatically.

3. Verify the bundle arrived:

   ```
   inbox
   ```

4. Stage the project (deploys to `staging.<hostname>`):

   ```
   stage myapp
   ```

5. Verify the staged deployment works, then promote to production:

   ```
   promote myapp
   ```

   Or, if staging reveals problems, abandon it:

   ```
   unstage myapp
   ```

To skip staging and deploy directly to production:

```
prod-deploy myapp
```

---

## Deploying a New Project (Git)

For projects hosted in a git repository.

1. Register the project:

   ```
   add-git-project <name> <repo-url> [--ref REF]
   ```

   For example:

   ```
   add-git-project myapp https://github.com/example/myapp.git
   ```

2. Stage or deploy:

   ```
   stage myapp
   promote myapp
   ```

   Or deploy directly:

   ```
   prod-deploy myapp
   ```

Deploy a specific git ref:

```
prod-deploy myapp --ref v1.2.3
```

---

## Staging a Project

Staging deploys a project alongside production at `staging.<hostname>`, allowing verification before promoting.

Stage the project:

```
stage myapp
```

After verifying the staging environment:

- **Promote** -- tears down staging and deploys to production:

  ```
  promote myapp
  ```

- **Unstage** -- tears down staging, production unchanged:

  ```
  unstage myapp
  ```

Staging is useful for:
- Verifying a new bundle before it goes live
- Testing configuration changes in a production-like environment
- Checking that routing and TLS work correctly

---

## Updating an Existing Project

Upload a new bundle and stage or deploy:

```
scp -O -P 922 myapp-v2.tar.gz deploy@<host>:
stage myapp
promote myapp
```

For git-based projects, deploy pulls the latest code:

```
prod-deploy myapp
```

---

## Previewing Changes

Before deploying, preview what would change:

```
diff myapp
```

This shows differences between the current production state and the pending bundle or git ref, without making any changes.

---

## Managing Secrets

Secrets are managed via the CLI. Two scopes are available:

### Project-level secrets

```
secrets set myapp DATABASE_URL=postgres://...
secrets get myapp DATABASE_URL
secrets list myapp
secrets unset myapp OLD_KEY
```

Project secrets are stored in `secrets.env` and injected into the project's containers.

Keys must be environment-variable names (letters, digits and underscores, not starting
with a digit). Values may contain spaces, tabs, `=` and any printable text, but not
newlines or other control characters, which would add lines to the env file. Either
violation is refused with an `ERROR:` and nothing is written. Store a multi-line value
(a PEM key, say) base64-encoded and decode it in the app.

The deploy shell parses each command with shell-style quoting. A command with an
unbalanced quote is rejected (`ERROR: cannot parse command`) rather than guessed at, so
quote a value containing spaces as a whole: `secrets set myapp 'GREETING=hello world'`.

### Host-level secrets

Shared across all projects on the host:

```
secrets set --host PUSHOVER_TOKEN=abc123
secrets get --host PUSHOVER_TOKEN
secrets list --host
secrets unset --host OLD_KEY
```

**Note:** `project.env` ships with the bundle and contains non-secret configuration. `secrets.env` is managed by the CLI and contains credentials. Do not confuse the two.

---

## Managing the Inbox

Bundles uploaded via scp land in the inbox automatically. Use the legacy scp protocol
(`scp -O`): SFTP, which OpenSSH 9+ uses for plain `scp`, is disabled for the deploy user
because sftp-server cannot be confined to the inbox.

List bundles in the inbox:

```
inbox
```

Remove old bundles:

```
inbox clean
```

---

## Checking Health

Run all health checks for one project (Docker container health, HTTP endpoint, smoke test):

```
check myapp
```

Run health checks for every registered project:

```
check-all
```

View a dashboard of all projects and their current status:

```
status
```

Get the same dashboard as machine-parseable JSON:

```
status --json
```

Health checks also run automatically every 5 minutes via a systemd timer. Failures trigger Pushover alerts after the configured threshold.

A project whose manifest or state files cannot be read does not stop the others being checked.
`check-all`, `status` and `health` print an `ERROR:` line naming the project and the file, write
an error entry to the operational log, and carry on with the rest of the fleet. `status` shows the
project as `ERROR` (`"raw_status": "error"` with an `error` field in `--json`) and exits 1.
`check-all` exits at least 1, and records an unreadable manifest in the project's health state so
the normal threshold alert fires with the cause. `check-all` also reports an unreadable host
config (`boxmunge.yml`), since alerts cannot be sent without it, and still runs the checks.

An alert counts as sent only when Pushover accepts it. If it is not delivered, the health check logs why (an `error` entry when the config cannot be read or the Pushover request fails, a `warn` entry when Pushover is not configured) and tries again on the next 5-minute tick until it gets through. The same applies to the critical alert for a stopped project and to the RECOVERED notice. Find these entries with `log --component health`.

---

## Reading Logs

View recent logs for a project (all services):

```
logs myapp
```

View logs for a specific service within a project:

```
logs myapp backend
```

Show more lines (default is typically 100):

```
logs myapp --tail 500
```

Live-tail logs (stream new output, press Ctrl-C to stop):

```
logs myapp --follow
```

View the boxmunge operational audit log:

```
logs --boxmunge
```

The operational log records every boxmunge action with timestamp, level, project, and message. It is the first place to check when something happened unexpectedly.

---

## Backups

Back up a single project (dump, compress, encrypt, store locally):

```
backup myapp
```

Back up all configured projects (this is what the 02:00 timer runs):

```
backup-all
```

Copy all local encrypted backups to the configured off-box remote (the 03:00 timer runs this), or one project's:

```
backup-sync
backup-sync myapp
```

### Snapshot kinds and retention

Every snapshot is named `<project>-<UTC timestamp>-<kind>.tar.gz.age`, for example `myapp-2026-03-30T020000-nightly.tar.gz.age`. Retention is counted separately for each kind, per project, so one kind never evicts another:

| Kind | Taken by | Local copies kept |
|---|---|---|
| `nightly` | `backup-all` (the 02:00 timer) | `backup.retention` in the manifest (default 7) |
| `predeploy` | `prod-deploy`'s pre-deploy snapshot (`deploy.snapshot_before_deploy`) | 5 |
| `preupdate` | the container-update timer, only when a pulled image changed and the project is about to be recreated | 3 |
| `prerestore` | `restore`, a safety snapshot of the data about to be replaced (unless `--no-safety-snapshot`) | 3 |
| `manual` | `backup <project>`, the MCP `backup` tool, the console, `self-test` | 5 |

After each backup, the oldest snapshots of that kind beyond its count are deleted. Archives from before kinds existed (`<project>-<timestamp>.tar.gz.age`) count as `nightly` and age out as new nightly backups arrive. Other files in `backups/` are never touched. `backup.retention` must be a whole number of at least 1; anything else fails the backup before it dumps.

### Off-site copies

`backup-sync` uses `rclone copy`, not `rclone sync`. The remote is an archive, not a mirror: a local prune never deletes an off-site copy, and neither does `project-delete`. boxmunge never deletes anything off-site, so bound the remote's size with a lifecycle rule on the bucket (for example, expire objects after 90 days). The layout on the remote is `<backup_remote>/<project>/backups/<snapshot>`, for both the full sync and `backup-sync <project>`.

`backup-sync` needs `backup_remote` in `boxmunge.yml` (for example `offsite:my-bucket/boxmunge`). A named remote such as `offsite` is defined in `/opt/boxmunge/config/rclone/rclone.conf`, which `install.sh` creates empty (`root:deploy`, mode 0640). Edit it as root, for example:

```ini
[offsite]
type = s3
provider = AWS
access_key_id = ...
secret_access_key = ...
region = eu-west-1
```

The directory is mounted read-only into the `boxmunge-system` container, so edits take effect on the next sync without a restart. Backends that rewrite their config to refresh OAuth tokens cannot save the refreshed token there; prefer static-key backends (S3, B2 and similar).

age and rclone run only inside the `boxmunge-system` container. If it is not running, `backup`, `backup-all`, `restore`, `test-restore` and `backup-sync` fail with an error rather than falling back to host tools. Start it with:

```
sudo docker compose -f /opt/boxmunge/system/compose.yml up -d --build
```

Restore from the most recent backup:

```
restore myapp
```

Restore from a specific snapshot:

```
restore myapp myapp-2026-03-30T020000-nightly.tar.gz.age
```

Before `restore` stops anything, it decrypts the snapshot and checks that it unpacks: it must be
non-empty, a gzip stream must decompress to the end, and a tar archive must list. It then takes a
safety snapshot of the current data, named `myapp-<timestamp>-prerestore.tar.gz.age` (the three newest are kept). If either
step fails, production is left running and untouched. Only then does it stop the project, restore
the data (the `restore_command` is limited to 10 minutes), and start every service again. The
services are started again whether the restore succeeded or failed. When it fails, the error names
the safety snapshot so you can put the previous data back:

```
restore myapp myapp-2026-10-13T120000-prerestore.tar.gz.age
```

The safety snapshot needs the backup service to be running and `backup.dump_command` to be set. If
it cannot be taken (for example, the database is down, which is why you are restoring), the restore
stops with an error. To restore anyway, without a safety snapshot:

```
restore myapp myapp-2026-03-30T020000.tar.gz.age --no-safety-snapshot
```

Safety snapshots sit alongside the nightly backups and are pruned by the same retention.

Verify that a backup restores successfully (non-destructive):

```
test-restore myapp
```

---

## Rolling Back

Undo the last deploy -- restore the pre-deploy snapshot and redeploy the previous state:

```
rollback myapp
```

You will be shown what snapshot will be restored and asked to confirm before anything changes.

---

## Deleting a Project

```
project-delete myapp
```

This removes the production and staging containers, the project directory (including its local
backups), the Caddy site configs, and every piece of per-project state: health, deploy, pause and
quarantine markers, CVE scan state, staging state, and container-update state. It then removes the
name from the allowlist. A project later created with the same name starts clean, not paused or
quarantined.

The containers are removed first. If that fails, `project-delete` stops with an error and deletes
nothing, so the compose files are still there for a retry. Fix the cause (usually Docker) and run it
again. If the containers are already gone and the error persists, delete anyway with:

```
project-delete myapp --force
```

`--force` warns that containers named `myapp-*` may still be running. Check with `docker ps` as the
supervisor user.

---

## Concurrent Operations

Every command that changes a project holds that project's lock while it works: `prod-deploy`,
`stage`, `promote`, `unstage`, `rollback`, `restore`, `backup`, `pause`, `resume`, `recover`,
`project-delete`, the daily `container-update` (for the whole backup, pull, recreate, and rollback
sequence), the CVE scan, and the 5-minute health check. Only one of them runs against a project at a
time.

If another operation holds the lock, an operator command fails at once and changes nothing:

```text
ERROR: Another operation is in progress for 'myapp'. Try again shortly.
```

Confirmation prompts are answered before the lock is taken, and the checks that decide whether the
command may act (paused, CVE-quarantined, monitor-stopped) are repeated once the lock is held. A
quarantine that lands while you are answering the prompt therefore still wins.

Timers treat a held lock as routine, not as a failure. The 5-minute health check skips the project
for that tick. `container-update` logs a warning (`Skipped myapp: project lock held by another
operation`), tries the project once more after the other targets, and otherwise leaves it for the
next day's run. A skip does not fail the run or send a Pushover alert. Nothing is recorded for a
skipped project, so one that is skipped day after day shows up as stale in `health`
(`container-updates`).

Webhook POSTs and the `resume` smoke-failure alert are sent without holding the project lock, so a
slow or unreachable endpoint cannot block other operations. A failed webhook delivery is logged as a
warning (scheme and host only, never the URL path) and does not fail the command.

---

## Pause and Resume

Take a project offline temporarily without tearing it down. Visitors see a styled 503 maintenance page branded "Scheduled maintenance" -- not a broken site.

Use pause for planned maintenance, post-incident triage, or while you reconfigure something risky:

```
boxmunge pause myapp --reason "rolling key rotation"
```

Containers are stopped via `docker compose stop`, so state is preserved on disk and resume is fast. While paused:

- Health checks, scheduled backups, and container-update sweeps skip the project
- `prod-deploy`, `stage`, and `promote` refuse to run against it
- `backup-sync` continues (it only copies; existing off-box snapshots are never removed)

To bring it back:

```
boxmunge resume myapp
```

`resume` pulls the latest images by default. This is a deliberate safety guarantee: a project that was paused for hours or days should not come back on stale, potentially vulnerable images.

For emergency overrides (e.g., the registry is unreachable and you need the site up now):

```
boxmunge resume myapp --skip-security-checks   # only if you accept the risk
```

This brings containers up on whatever images are already cached locally. Do not use it casually -- you are explicitly accepting that the project may be running known-vulnerable code.

### Caddy maintenance-dir mount

The styled 503 page is served by Caddy from `/etc/caddy/maintenance` (mounted from `/opt/boxmunge/caddy/maintenance/` on the host). The mount is fixed in `caddy/compose.yml`. If you ever hand-edit the Caddy compose file without changing the bundled version, `install.sh`'s file-equality check (`cmp -s`) will not detect the drift and `docker compose up -d` will not recreate the container -- the running Caddy will keep its stale mounts.

If the maintenance page does not render after an upgrade, force a Caddy recreate explicitly:

```
sudo docker compose -f /opt/boxmunge/caddy/compose.yml up -d --force-recreate
```

Then `curl -I https://your-paused-host/` and confirm it returns `HTTP/1.1 503` with `Retry-After: 3600`.

---

## Host Maintenance

Verify the host is correctly configured:

```
doctor
```

Send a test Pushover notification:

```
test-alert
```

Show active Caddy sites and TLS certificate expiry dates:

```
caddy-status
```

See all projects, status, last-check and deployed-at timestamps:

```
status
```

List the project allowlist (registered project names):

```
project-list
```

---

## Troubleshooting

### Project won't start

Check the project logs for error output:

```
logs myapp
logs myapp backend
```

Validate the manifest and compose file for problems:

```
validate myapp
```

Preview the current project state:

```
diff myapp
```

If deeper investigation is needed (inspecting files, Docker state, system config), this requires the **supervisor** user.

---

### Manifest validation rejects a wildcard host

If `validate` or `deploy` reports `wildcard host '*.example.com' requires 'allow_wildcard_hosts: true' at the manifest top level`, that's the deliberate opt-in gate for wildcards. boxmunge runs single-tenant, but a wildcard on one project can still capture traffic intended for adjacent projects on the same Caddy. Add the flag explicitly when you mean it:

```yaml
allow_wildcard_hosts: true
hosts:
  - "*.example.com"
```

Plain hostnames don't need the flag. See `SECURITY.md` for the routing-isolation trade-off.

---

### Container crash-loops with "Read-only file system" (v0.9+)

v0.9 makes read-only rootfs an active default. If your container writes to a path outside `/tmp` (e.g. nginx writes `/var/cache/nginx/client_temp`, postgres writes `/var/lib/postgresql/data`, your app writes `/var/log/myapp/...`), the first write fails and the container exits with `Read-only file system`.

Boxmunge surfaces this automatically. Three places to look:

- **Deploy output** — an 8-second post-`compose up` scan emits a `[HINT]` block naming the offending path:

  ```text
  [HINT] services.web reports read-only filesystem errors for path(s) '/var/cache/nginx'.
         Add the path(s) to manifest.yml at services.web.writable.ephemeral
         (or .persistent if data should survive restart). See: agent-help writable.
  ```

- **Smoke-failure output** — when a smoke test fails and recent logs contain a read-only-fs error, the failure message is enriched with the same hint.
- **`boxmunge logs <project>`** — non-follow mode appends a writable-hint postscript when the captured buffer contains read-only-fs errors.

Fix it by declaring the write path under `services.<name>.writable` in the manifest:

```yaml
schema_version: 3
services:
  web:
    writable:
      ephemeral:           # tmpfs — wiped on container restart
        - /var/cache/nginx
        - /var/run
      persistent:          # named docker volumes — survive restart
        - name: dbdata
          mount: /var/lib/postgresql/data
```

Then `deploy` (or `upgrade`) the project. The overlay generator regenerates `compose.boxmunge.yml` with the requested tmpfs/volumes, and the container starts cleanly.

#### Externally-managed services

If the app needs unusual writability that boxmunge's abstraction doesn't model (bind mounts, shared host paths, esoteric tmpfs options), opt out of manifest management for that service:

```yaml
services:
  legacy:
    writable:
      external: true        # boxmunge defers all tmpfs/volumes to your compose.yml
```

This declares "I'll handle writability via compose.yml directly for this service." Boxmunge emits no tmpfs (not even `/tmp`) and no volumes. Compose-side `tmpfs:` and `volumes:` declarations are accepted as-is. An `[INFO]` warning fires every deploy as a visible reminder of the delegated state.

`read_only: true` still applies under `external` — to opt out of read-only rootfs separately, declare `read_only: false` in compose.yml (which emits a `[WARNING]` every deploy and incurs a CVE hardening penalty).

#### Conflict errors

If compose.yml declares `tmpfs:` or named `volumes:` for a service while the manifest has no `writable:` block (or has `ephemeral/persistent` already), deploy fails:

```
ERROR: services.web: compose.yml declares tmpfs but the manifest has no writable: block for this service.
Boxmunge owns this surface by default. Declare paths in services.web.writable.ephemeral (for tmpfs)
or services.web.writable.persistent (for named volumes), or set services.web.writable.external: true
to manage writability in compose.yml directly.
```

Pick one: declare in manifest, restructure the conflict away, or switch the service to `writable.external: true`.

`boxmunge security <project>` shows the per-service writable state (default / manifest-managed (N ephemeral, M persistent) / externally-managed) at a glance.

---

### Smoke script fails after upgrade with "permission denied" on `ping` or `traceroute`

v0.5 hardening drops `NET_RAW` from every container by default — so `ping`, `traceroute`, and a handful of HTTP probe libraries that fall back to ICMP will fail with `Operation not permitted`. Most apps do not need `NET_RAW`; if your smoke script genuinely does, opt back in by adding to the project manifest:

```yaml
security:
  cap_add: [NET_RAW]
```

Place at the project level to apply to every service, or under a specific service to scope. After redeploying, `security <project>` will show `NET_RAW` no longer in `cap_drop` and present in `cap_add`. See `agent-help security` for the full hardening model.

---

### Caddy isn't routing

Check Caddy's status and active sites:

```
caddy-status
```

Check the project's health and routing config:

```
check myapp
validate myapp
```

If the config looks stale, redeploy to regenerate:

```
prod-deploy myapp --no-snapshot
```

If deeper Caddy investigation is needed (container logs, config file inspection), this requires the **supervisor** user.

---

### Project in CRITICAL (stopped) state

This state means the smoke test exited with code 2 -- a critical failure that caused boxmunge to stop the project containers. The project will not restart automatically.

The stop is sticky. Later 5-minute health checks do not run smoke against the stopped project, do not change its recorded failure reason, and do not send more alerts. `check-all` reports it as `CRITICAL (stopped by the health monitor ...)`, and `health` lists it under `lifecycle` as `monitor-stopped`. The stop stays in place until you run `recover`, or until a later deploy, rollback, or resume starts the project successfully.

Check the dashboard to confirm the state:

```
status
```

Check logs from just before the containers were stopped:

```
logs myapp --tail 200
```

Once you have identified and fixed the underlying issue, restart the same build with `recover` (no image pull, no rebuild; it restores routing and runs the smoke test):

```
recover myapp
```

Or, if the fix needs new code, redeploy:

```
prod-deploy myapp
```

---

### Host doctor reports problems

Run doctor to see the current list of issues:

```
doctor
```

Each item in the output is labelled OK, WARN, or FAIL with a description. Address each FAIL, then each WARN, then re-run `doctor`.

Issues requiring system-level investigation or repair (systemd timers, file permissions, Caddy container state) require the **supervisor** user.

---

### Need to recover from a bad deploy

**Option 1: Rollback** (fastest if the previous state was good)

```
rollback myapp
```

**Option 2: Deploy a known-good bundle or ref**

Upload a known-good bundle and deploy it, or deploy a specific git ref:

```
prod-deploy myapp --ref v1.1.4
```

---

## Verifying Platform Health

Run a non-destructive audit:

```
health
health --json
```

Exit codes: 0 = healthy, 1 = warnings, 2 = issues requiring attention.

## Command Exit Codes

The boxmunge CLI uses these conventions across mutating commands
(`deploy`, `stage`, `promote`, `resume`, `upgrade`):

- `0` — success
- `1` — generic operational failure (image pull, smoke test, Caddy reload, etc.)
- `2` — usage error (unknown flag, missing argument) or critical health (`check`)

Every command rejects a flag it does not implement with exit 2, `ERROR:` and its usage on
stderr, and runs nothing. That includes `--dry-run`: only `prod-deploy`, `stage`, `promote`,
`unstage`, `upgrade` and `container-update` support it, and every other command (for example
`project-delete`, `rollback`, `restore`, `pause`, `secrets set`) refuses it instead of acting.
`check-all` accepts only `--read-only`; a typo such as `--raed-only` is an error, not a run of
the mutator. `-h` or `--help` on any command prints its usage, exits 0, and never runs it.
- `3` — compose hardening rejection (validate_user_compose found a
  policy-violating key in the project's `compose.yml`; the deploy/stage/
  promote/resume aborted before touching containers)

Exit code 3 is reserved for hardening rejections so an operator can
distinguish a security-policy failure ("fix your compose.yml") from a
generic operational failure ("retry / investigate logs").

## Proving Backup/Restore Works

Run the self-test (deploys a canary, exercises backup/restore, tears down):

```
self-test
```

## Upgrading the Platform

Apply platform updates:

```
upgrade
```

`upgrade` installs the newest release of any class. Every release has a
class, and the auto-update timer (every 6 hours) decides by class what to
install without you:

| Class | Applied automatically? |
|---|---|
| `security` | Always. |
| `breakfix` (a critical non-security fix) | Yes, unless `auto_update.breakfix` is `false` in `boxmunge.yml`. |
| `feature` | Never. Run `upgrade` when ready. |

Automatic updates stay on the box's own `major.minor` line (a 0.11.x box
gets 0.11.y, never 0.12.0). To take security releases only, set this in
`/opt/boxmunge/config/boxmunge.yml`:

```yaml
auto_update:
  breakfix: false
```

The value must be `true` or `false`; anything else is a configuration error
and auto-update stops with an `ERROR:` until it is fixed.

Every automatic update, whatever its class, gets the same protection: the
signature is verified, the release runs a 6-hour probation, and a release
that fails is rolled back and blocklisted on this box. The auto-update log
entry names the class that was applied (`log --component auto-update`).

Releases are discovered through the version-check service at boxmunge.dev.
If it is unreachable or answers in an unexpected shape, auto-update falls
back to the GitHub releases list (a release marked `[security]` or
`[breakfix]` in its title or notes) and logs a warning.

Pin to a specific release (for example to roll forward past a bad one):

```
upgrade --target 0.11.2
```

`--target` only moves forward. It refuses a version below the installed one and a
version blocklisted on this box (one that failed an earlier upgrade and was rolled
back). To install such a version deliberately, an operator runs the shim directly
as `supervisor`:

```bash
sudo /opt/boxmunge/bin/boxmunge-upgrade force-target 0.11.1   # ignore blocklist and floor
sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist 0.11.1  # forget a failed version
```

Neither is available from the deploy shell or MCP.

## Querying Logs

```
log --project myapp --level error --since 24h
log --json
log --project myapp --containers
```

---

## CVE Policy

boxmunge enforces a CVE policy on every deployed image: a daily Trivy
scan, a posture-based quarantine for findings that cross the threshold,
and an operator-driven suppression workflow for findings reviewed and
judged not exploitable.

Scan cadence:

- Daily at 03:00 (±30 min jitter) via `boxmunge-cve-scan.timer`
- On every `prod-deploy`, `stage`, `promote`, `resume`, and image update
- Ad-hoc:

  ```
  boxmunge security scan              # all projects
  boxmunge security scan myapp        # one project
  ```

Inspect state:

```
boxmunge security                    # fleet summary
boxmunge security myapp              # per-project view
boxmunge security --json             # machine-readable
```

Suppress a CVE that has been reviewed:

```
boxmunge security suppress CVE-2026-1234 \
  --project myapp --until 2026-08-01 \
  --reason "Endpoint not exposed in our config; vuln path unreachable."
```

If a project gets auto-quarantined, the maintenance page goes up and a
critical Pushover alert fires. Investigate, then either wait for an
upstream fix or suppress, then:

```
boxmunge security resume myapp
```

`security resume` re-scans first and refuses to lift if a quarantine-
level finding still applies.

Audit trails for the CVE machinery live in the structured log:

```
boxmunge log --component cve-scan
boxmunge log --component cve-suppress
```

For the full reference (posture tiers, hardening penalty, suppression
schema, alerts) see `agent-help cve` (CVE_POLICY.md). For a step-by-
step incident playbook see `agent-help cve-incident`.

---

## Agent Access via MCP

Configure your AI agent (Claude Code, Cursor, etc.) to use boxmunge via MCP:

```json
{
  "mcpServers": {
    "boxmunge": {
      "command": "ssh",
      "args": ["-p", "922", "deploy@your-box.example.com", "mcp-serve"]
    }
  }
}
```

The agent will discover all available tools automatically. Available tools include: prod-deploy, stage, promote, backup, restore, rollback, health, log, secrets, upgrade, and more.

`restore` and `rollback` replace a project's running state, so they only run when called with
`confirm: true`. `upgrade` goes through the same root upgrade shim as the shell's `upgrade`
(optionally with `version` for `upgrade --target`). Each result's `messages` carries the
command's stdout and stderr.

Requires the `mcp` package on the server. It is not installed by default — add it
to the server's environment with:

```
/opt/boxmunge/env-active/bin/pip install 'mcp>=1.0'
```

Note: `boxmunge` on PyPI is the *client* CLI. The server package is
`boxmunge-server` and is installed from GitHub releases, not PyPI.
