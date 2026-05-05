# boxmunge Operations Guide

Step-by-step instructions for common tasks on a boxmunge-managed server.

All operations use boxmunge commands. For detailed help on any command, run `help <command>`.

---

## Deploying a New Project (Bundle)

The standard workflow for deploying a project from a bundle.

1. Build a bundle locally (generates a ULID if `id` is missing from the manifest):

   ```
   boxmunge bundle ./myapp
   ```

2. Upload the bundle to the server:

   ```
   scp -P 922 myapp.tar.gz deploy@<host>:
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
deploy myapp
```

---

## Deploying a New Project (Git)

For projects hosted in a git repository.

1. Register the project:

   ```
   add-git-project myapp --repo https://github.com/example/myapp.git
   ```

2. Stage or deploy:

   ```
   stage myapp
   promote myapp
   ```

   Or deploy directly:

   ```
   deploy myapp
   ```

Deploy a specific git ref:

```
deploy myapp --ref v1.2.3
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
scp -P 922 myapp-v2.tar.gz deploy@<host>:
stage myapp
promote myapp
```

For git-based projects, deploy pulls the latest code:

```
deploy myapp
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
secrets set myapp DATABASE_URL postgres://...
secrets get myapp DATABASE_URL
secrets list myapp
secrets unset myapp OLD_KEY
```

Project secrets are stored in `secrets.env` and injected into the project's containers.

### Host-level secrets

Shared across all projects on the host:

```
secrets set --host PUSHOVER_TOKEN abc123
secrets get --host PUSHOVER_TOKEN
secrets list --host
secrets unset --host OLD_KEY
```

**Note:** `project.env` ships with the bundle and contains non-secret configuration. `secrets.env` is managed by the CLI and contains credentials. Do not confuse the two.

---

## Managing the Inbox

Bundles uploaded via scp land in the inbox automatically.

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

Back up all configured projects:

```
backup-all
```

Sync all local encrypted backups to the configured off-box remote:

```
backup-sync
```

Restore from the most recent backup:

```
restore myapp
```

Restore from a specific snapshot:

```
restore myapp myapp-2026-03-30T020000.tar.gz.age
```

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

## Pause and Resume

Take a project offline temporarily without tearing it down. Visitors see a styled 503 maintenance page branded "Scheduled maintenance" -- not a broken site.

Use pause for planned maintenance, post-incident triage, or while you reconfigure something risky:

```
boxmunge pause myapp --reason "rolling key rotation"
```

Containers are stopped via `docker compose stop`, so state is preserved on disk and resume is fast. While paused:

- Health checks, scheduled backups, and container-update sweeps skip the project
- `deploy`, `stage`, and `promote` refuse to run against it
- `backup-sync` continues (off-box copies of existing snapshots are unaffected)

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
deploy myapp --no-snapshot
```

If deeper Caddy investigation is needed (container logs, config file inspection), this requires the **supervisor** user.

---

### Project in CRITICAL (stopped) state

This state means the smoke test exited with code 2 -- a critical failure that caused boxmunge to stop the project containers. The project will not restart automatically.

Check the dashboard to confirm the state:

```
status
```

Check logs from just before the containers were stopped:

```
logs myapp --tail 200
```

Once you have identified and fixed the underlying issue, redeploy:

```
deploy myapp
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
deploy myapp --ref v1.1.4
```

---

## Verifying Platform Health

Run a non-destructive audit:

```
health
health --json
```

Exit codes: 0 = healthy, 1 = warnings, 2 = issues requiring attention.

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

Security releases are applied automatically every 6 hours.

## Querying Logs

```
log --project myapp --level error --since 24h
log --json
log --project myapp --containers
```

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

The agent will discover all available tools automatically. Available tools include: deploy, stage, promote, backup, restore, rollback, health, log, secrets, and more.

Requires the `mcp` package on the server: `pip install boxmunge[mcp]`
