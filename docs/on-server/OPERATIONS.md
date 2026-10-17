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

`prod-deploy` and `stage` fetch `origin`, then resolve the ref (`--ref`, else the manifest's `ref`)
once, to a full commit SHA: a branch is origin's branch as just fetched (never a stale local
one), a tag is a tag, and a commit is named by all 40 characters. An abbreviated SHA, and a name
that is both a branch and a tag of origin, are refused (give the full SHA). The deploy then checks
that commit out detached in `repo/`; there is no `git pull`. Deploy state records the full SHA. A
deploy runs in the same install transaction as a bundle deploy (see "An interrupted or failed
install"), and its pre-deploy snapshot is taken with the running release's manifest before
anything is checked out.

`stage` of a git project checks the resolved commit out in a clone of its own in the slot
(`.releases/staged/release/repo/`), beside copies of the project directory's other release files
(`.env`, `project.env`, `boxmunge-scripts/`, ...); production's `repo/` and its `HEAD` never
move. `promote` then deploys exactly that SHA, even if the branch has moved since, and `unstage`
leaves production on its own commit. A `.gitmodules` is staged with a warning: submodules are
checked out in neither production nor staging. A commit whose `.gitattributes` assigns a `filter`
(Git LFS, for example) cannot be staged, because the staged checkout runs no filter drivers and
would not have production's files; nor can one with a symbolic link that resolves outside the
staged release. Deploy such a commit with `prod-deploy`. As a bundle may not ship a top-level
`*-staging` entry, a git stage is refused while the project directory holds one that is neither
production's data nor staging's copy: rename it.

boxmunge always runs git as the deploy user, also when a command runs as root (with `sudo`):
`repo/` must be deploy's, origin must accept deploy's SSH key or credentials, and git reads
deploy's own config and the system's (`/etc/gitconfig`), the same in the deploy shell and under
`sudo`. An upgrade's dry run and apply warn about each git project whose `repo/` deploy does not
own (one cloned, or fetched into, as root), naming the fix: `chown -R deploy:deploy <p>/repo`.

A git project's `manifest.yml` and `compose.yml` are symlinks into `repo/`, so every deploy
reads the repository's files. boxmunge never writes them. When an upgrade raises the manifest
schema, a git project's manifest is migrated in memory each time it is read, and the upgrade
logs a warning and sends one alert (per schema change) asking you to set `schema_version` to
the current version in the repository. Nothing breaks in the meantime. If the repository's
manifest has no `schema_version` at all, the alert asks you to add one.

Upgrades by earlier releases replaced a git project's `manifest.yml` link with a regular file, after
which deploys read that frozen copy instead of the repository. `upgrade --dry-run`, `upgrade`
(once, with an alert), `check <project>` and `doctor` report such a project with the commands
that fix it. Compare the two files first, and re-link once the repository's file is the one to
use:

```
diff /opt/boxmunge/projects/myapp/manifest.yml /opt/boxmunge/projects/myapp/repo/manifest.yml
ln -sfn repo/manifest.yml /opt/boxmunge/projects/myapp/manifest.yml
```

---

## Staging a Project

Staging deploys a project alongside production at `staging.<hostname>`, allowing verification before promoting.

Stage the project:

```
stage myapp
```

`stage` refuses a `compose.yml` that pulls services in through `include:` or
`extends: file:`: it rewrites bind mounts to `-staging` copies only in
`compose.yml` itself, so those services would share production's data. Move
the services into `compose.yml` to stage them.

After verifying the staging environment:

- **Promote** -- tears down staging and deploys to production:

  ```
  promote myapp
  ```

- **Unstage** -- tears down staging, production unchanged:

  ```
  unstage myapp
  ```

The staged release lives in its own tree, `.releases/staged/` (the slot), and staging runs from
there: `stage` never writes production's files, and production's running containers are only
stopped for a `staging.copy_data` copy, then started again. A stage that fails, first or re-stage,
is torn down completely. `promote` deploys the staged release (never a newer bundle that arrived in
the inbox meanwhile). `unstage` takes staging down and drops the slot; if it cannot remove the
staging containers it keeps the slot, records why, and prints the commands to finish by hand.

`promote` is an ordinary production deploy whose release is the staged one, in the same install
transaction as `prod-deploy`. A `promote` that fails before any production container is touched (a
failing `pre_deploy` hook) leaves the install open, as a failed `prod-deploy` does, and the stage as
it was: rerun `promote`, or deploy a fix. Once it has started the staged release's containers,
production runs that release even if a later step fails (`compose up` errors part-way, Caddy
rejects the site, smoke fails): the error says `production now runs <ref>` and what `rollback`
would do, and the displaced production release becomes the previous release, exactly as after a
failed `prod-deploy`. `rollback` returns to it with the data snapshot taken (with production's own
manifest) before the promotion. The stage is then marked retired, so it is never promoted twice;
staging is left up and `unstage` removes it. If staging cannot be torn down after a successful
promotion, `promote` exits 1 and asks you to run `unstage`. A promote that is killed is finished by
running `promote` again, which resumes the install from where it stopped (after the switch it
does not run the `pre_deploy` hook again or take a new snapshot). If the switch had already ended,
the rerun only tears staging down, and still exits 1 with the rollback options if the switch failed.
The `Promoted` log line and `promote` webhook go out once per promotion, however often it is rerun.
A killed `unstage` is likewise finished by running it again.

`prod-deploy` and `rollback` work while a release is staged; staging is left as it is, and the
next `promote` keeps whatever production then runs as its previous release. Before anything
changes, each proves production's next release shares nothing with staging (as `stage` does,
below) and refuses with "Nothing was changed" if it would. Such a release whose `compose.yml` uses
`include:` or `extends: file:` cannot be checked this way and is refused: unstage first, or move
those services into `compose.yml`. A git project's `prod-deploy` and `rollback` check the commit
from a scratch clone of it, so they are refused for a commit `stage` would refuse (a filter
attribute, a link out of the tree).

Staging and production share no Docker resource. Before installing anything, `stage` resolves
staging from the staged release, and production both as it runs and as it would run once the
release is promoted, with `docker compose config` (`-p myapp` and `-p myapp-staging`). It refuses
if staging would share a volume, network, network alias, container name or bind-mount source with
either, or build an image tag production runs, and if a service needs an `env_file` that does not
exist (staging could not start: create the file, for `secrets.env` with `secrets set`, or mark it
`required: false`). It checks again before starting anything. The staging copy of
`compose.yml` drops explicit volume and network `name:` lines (validation only allows the project's
own name, which Compose would choose anyway) and `ports:`. Bind mounts of release
code and configuration (`./appconfig:/etc/app:ro`, config and secret `file:` entries) work in both
environments without copying any data: production mounts its project directory's, staging the
staged release's own in `.releases/staged/release/`.

The staged release lives in `.releases/staged/`, so the project directory stays production's and
production starts as usual during a stage (upgrade restarts, container updates, `recover`,
`resume`, `security resume`, `restore`). A release staged by boxmunge 0.10.1 is different: it put
the staged release's files in the project directory. For such a project `stage`, `unstage`,
`promote`, `prod-deploy`, `rollback`, `restore`, `resume`, `recover`, `pause` and `data adopt`
refuse directly, naming `boxmunge-server legacy-stage <project>`; background starts (upgrade
restarts, container updates) and `security resume` are refused with a "start refused" alert (see
Troubleshooting). If boxmunge cannot tell whether such a stage is on disk (for example `state/`
cannot be read), it refuses the same way and says so; the health check then runs no smoke test
and reports a warning, a backup is skipped with an alert, a due CVE quarantine is not taken (the
scan reports why), and an upgrade leaves the project as it is with a high-priority alert. Fix the
cause (usually permissions) and retry; a project the upgrade left this way keeps its previous
configs until you deploy, resume or recover it. Its
running containers are left as they are. How to resolve it: "Upgrading from 0.10.1 with a
release staged".
Until it is resolved:

- the health check runs no smoke test and takes no critical action for it, reports it as
  `legacy-stage`, and alerts (high priority) at most once a day;
- backups continue with the manifest of the release the containers run, told from the evidence
  `legacy-stage` prints; if that evidence cannot be read (Docker unavailable, an unreadable
  reflog or `.releases/prestage/`, a commit that does not resolve), the backup is skipped with
  an alert naming the cause (a never-deployed git project's is skipped without one: it has no
  data). For a git project the dump still runs through the project's
  `compose.yml`, which is the staged checkout's: if the staged release renamed the backup
  service, the backup fails with an error until the stage is resolved;
- a CVE quarantine is held, not taken (it would stop production), with a high-priority alert
  naming the finding. Scans and their reports run as usual.

A bind mount, config or secret file in a data directory (any directory a release has mounted
read-write) or another server-owned entry (`data/`, `secrets.env`) points staging at the entry's
`-staging` copy in the project dir: `./uploads/img` becomes `<project>/uploads-staging/img`,
an absolute path. Staging never reads
production's copy, so a config or secret `file:` in a data directory (`./data/key.pem`) must exist
in staging's copy (`./data-staging/key.pem`): `stage` copies it with `copy_data`, and without
`copy_data` refuses, naming the file to put there. Such a file may not sit in a directory a service
of the release mounts read-write: a container could replace it with a symlink to any host file,
which Docker would mount on the container's next start, so validation refuses it (SECURITY.md,
"Project isolation").

Staging builds from the staged release. A `build` context, `dockerfile` or additional context
that names release code by absolute path in the project dir (`<project>/src`) is staging's
staged copy of it; one in a data directory or another server-owned entry, or one in `.releases/`
or `repo/`, is refused. So is an absolute `dockerfile` in the project when the context is not:
use paths relative to the release. `stage` also checks what each build input resolves to (with
`${VAR}` filled in) and refuses one in the project dir outside the staged release.

Two behaviour changes in this release:

- staging's copy of a nested data mount moved: `./data/db` used to become `./data/db-staging`
  (inside production's `data/`), and now becomes `./data-staging/db`. The old copies are not used
  any more. Nor are the old `-staging` copies of release code (`appconfig-staging`): staging now
  mounts the staged release itself. `unstage` lists any of either it finds, with the command to
  delete them, but does not delete them itself: inside production's data directory boxmunge
  cannot tell them from the app's own files, and a code copy may hold what an operator put there;
- `stage` refuses a service that mounts the whole project directory (`.:/app`), which staging and
  production cannot each have a copy of. Mount the subdirectories the service needs instead.

Each environment mounts its own release's `boxmunge-scripts/`: production's smoke checks run the
project directory's, staging's the staged release's, so a smoke check that only the staged release
passes does not fail production. Production switches to the new scripts when `promote` installs
them. The `.releases/live-scripts/` copy boxmunge 0.10.1 mounted for production is removed after
production's next full start once no container mounts it.

Staging keeps its own data between stages. To start it from a copy of production's, set
`staging: {copy_data: true}` in the manifest. `stage` then:

1. stops the previous staging (re-stage) and creates the new one without starting it;
2. pairs every data store the staged release mounts with production's store of the same name:
   named volumes (including `writable.persistent` ones), bind-mounted data paths and config or
   secret files in data directories, taken from the release production actually runs, not the
   staged one;
3. checks every production source exists (a missing volume is never created empty) and refuses if
   any staging container is running;
4. stops production's running containers, empties each staging destination completely (hidden
   files included; a staging copy of the wrong type, such as a directory where production has a
   file, is removed with a `NOTE`), copies production's data in, and starts production again whatever happened,
   even if it was interrupted. If production cannot be started again, `stage` fails with
   `PRODUCTION IS DOWN` and the `docker start` command to run. If `stage` itself was killed during
   the copy, the slot's `production_stopped` marker names the containers it stopped: the next health
   check (or `stage`, `unstage` or `recover`) starts them again and alerts, and the health check
   never applies its critical stop while the marker stands. After such a start the health check runs
   smoke on its next run; while an install is open it reports the
   install instead and starts nothing. A start that keeps failing is reported on every run and
   alerted once per error. If the slot's `meta.json` cannot be
   read, the health check cannot tell, so it reports the project `CRITICAL`, alerts once and leaves
   production alone: run `recover <project>` (it starts production with its compose files), then
   `unstage <project>`. `unstage` and a new `stage` replace such a slot, and with it any marker;
   each logs a warning and sends a priority-1 alert naming `recover <project>`. `pause` takes the
   stop over (`resume` starts production);
5. starts staging only after every copy succeeded.

The copies run in the data helper, a short-lived container from the box's own `boxmunge-system`
image (`boxmunge.invalid/system/system`, never pulled) running as root with no network, a read-only
root filesystem and only the capabilities a copy needs, so owners and 0600 files carry over;
production's stores are mounted read-only. A symlink on the way to a store or a copy (for
example `data-staging/a` pointing elsewhere) makes `stage` refuse the copy before anything is
written; remove the link and stage again. If that image is missing, `stage` says to build it with
`docker compose -f /opt/boxmunge/system/compose.yml build`. On a box with user-namespace remapping, a
single-file store directly in the project directory (`./app.db`) is refused before anything stops:
mount a directory holding the file instead (`./db/app.db`).

If the staged release renames a store (production uses `pgdata`, the staged release `newdata`),
`stage` refuses until the manifest says where the data comes from:

```yaml
staging:
  copy_data:
    sources:
      newdata: pgdata   # staged store: production store
      cache: null       # not copied: staging keeps its own
```

Name a volume as `compose.yml` names it, a `writable.persistent` entry by its `name`, or a bind
mount as `./path`. A staged store with no production counterpart is left as staging has it, as
long as every production store is copied somewhere. If a copy fails, production is started again,
staging is not started and the stage cleans up like any failed stage; run `stage` again to retry
(each destination is emptied first) or `unstage`. With `copy_data` set but nothing to copy, `stage`
fails rather than staging on stale data.

`unstage` (and `promote`, which ends with it) removes `-staging` copies of data directories the
production release no longer mounts, logging each one; copies of directories production still
mounts are kept for the next stage. Staging's named volumes are kept. Only staging's own copies
are ever mounted or removed: the copy of an entry production mounts or records as data, or one the
staged slot records that staging created. A `-staging` entry in the project dir that is neither
(release code an older bundle shipped, or an operator's) makes `stage` refuse a release that would
mount it ("is not staging's copy"), and `unstage` reports and leaves it. Rename it in the release.

A stage that fails after installing its release (staging containers fail to start, the staging data
copy fails, Caddy rejects the staging site) cleans up after itself: staging containers, the staging Caddy site and compose files are
removed and the production release's files are put back. `unstage` removes whatever a stage left
behind even if that stage never got as far as recording itself active, so it can always be used to
clean up; with nothing staged it reports `No staging found` and exits 1. If the staging containers
cannot be removed (Docker errors), nothing else is removed: the staging compose files and site stay,
the staging state records `cleanup_incomplete`, and running `unstage` again retries.

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

For git-based projects, deploy fetches origin and checks out the commit the manifest's `ref`
names now:

```
prod-deploy myapp
```

A release that stops bind-mounting a data directory (say `./uploads`) does not delete it: the
deploy keeps it and prints `WARNING: uploads/ holds data but this release's compose.yml does not
mount it`. Once neither the running release nor the rollback target needs that data, delete it on
the server as root (`rm -rf /opt/boxmunge/projects/myapp/uploads`, and its `uploads-staging` copy if
there is one). Until then, a bundle that ships an `uploads/` of its own is refused.

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

Values are literal: the container receives exactly what you set, and `secrets get`
prints exactly that. `$`, `${VAR}`, ` # `, quotes, backslashes and leading or trailing
spaces are not interpreted. The one value Compose's env-file format cannot carry
literally is one that ends in an odd number of backslashes or has an odd number of
backslashes right before a `'`; `set` refuses it (base64-encode it instead).
Concurrent `set`/`unset` calls on the same scope are serialised, so none is lost.
boxmunge needs Docker Compose 2.35 or newer (older releases cannot run its compose validation):
`install.sh` refuses to install or upgrade with an older one, and `doctor` reports it.
Upgrade with `apt-get install --only-upgrade docker-compose-plugin`.

Secrets set by boxmunge before literal values were stored unquoted, and Compose
interpreted `$`, ` #`, surrounding quotes and spaces in them. Such a value is left
exactly as stored, so containers keep receiving what they did, until you set it again.
`secrets list` and `secrets set` warn which keys these are, and `secrets get` on one
fails, showing the stored text: check what the app expects and `secrets set` it.
(`STAGING_AUTH_USER`/`STAGING_AUTH_PASS` are read, and printed by `get`, as before, so
stage keeps working.) An old value whose quote does not close exactly at the end of its
line can make Compose read the following lines into it. While one exists, other writes
to that scope are refused, since they could alter what containers receive; the error
lists each such key with the `secrets unset`/`secrets set` commands that clear it, one
at a time.
Keys stored before key names were validated (`MY-KEY`, `app.key`) are kept too, since
Compose still passes them on; `list` warns about them. Set the value under a valid name,
update the app, then remove the old one by its exact name: `secrets unset myapp 'MY-KEY'`.

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

Bundles uploaded via scp land in the inbox automatically, renamed to
`<project>-<timestamp>.tar.gz`. Use the legacy scp protocol (`scp -O`): SFTP, which OpenSSH 9+ uses
for plain `scp`, is disabled for the deploy user because sftp-server cannot be confined to the inbox.

`prod-deploy` and `stage` take the project's newest bundle, or the one named with `--ref` (the full
bundle name, or a prefix of its timestamp that matches exactly one bundle). A bundle belongs to a
project only when its name is exactly `<project>-<timestamp>.tar.gz`, so deploying `foo` never picks
up a `foo-bar` bundle. Once a bundle is deployed it moves to `inbox/.consumed/`, together with that
project's older bundles. A bundle that fails validation stays in the inbox.

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
`check-all`, `backup-all`, `status` and `health` print an `ERROR:` line naming the project and the file, write
an error entry to the operational log, and carry on with the rest of the fleet. `status` shows the
project as `ERROR` (`"raw_status": "error"` with an `error` field in `--json`) and exits 1.
This includes a quarantine record (`state/deploy/<project>.quarantined.json`) that is not JSON or
lacks a field boxmunge writes (`quarantined_at`, `cve_id`, `severity`, `effective_severity`,
`explanation`, `image_ref`): `status`, `security` and `security <project>` all name the file in
an `ERROR:` line and exit 1, where `status` used to show the row with `-` placeholders. A scan
does not rewrite an existing record, and lifting the quarantine needs the restart policies it
holds, so repair the file or restore it from a backup.
`check-all` exits at least 1, and records an unreadable manifest in the project's health state so
the normal threshold alert fires with the cause. `check-all` also reports an unreadable host
config (`boxmunge.yml`), since alerts cannot be sent without it, and still runs the checks.

The project registry, `state/projects.txt`, holds one project name per line. Every line is checked
as a project name when it is read. A line that is not one (`../etc`, a reserved name such as
`caddy` or `<x>-staging`) is reported as `projects.txt:<line>` with the reason. The nightly
`security scan` still scans every valid project, then alerts on the bad line and exits 1;
`security`, `health` and `doctor` name it too. Every valid project keeps working: deploys, stages
and the other per-project commands only ask whether their own name is registered, and
`project-add`/`project-delete` keep the bad line as it is when they rewrite the file. Listings
(`project-list`, `projects.list`) fail naming the line rather than list the registry with it left
out. Correct or delete the line as root.

An alert counts as sent only when Pushover accepts it. If it is not delivered, the health check logs why (an `error` entry when the config cannot be read or the Pushover request fails, a `warn` entry when Pushover is not configured) and tries again on the next 5-minute tick until it gets through. Without Pushover keys the `warn` entry is written at most once a day, because the retry would otherwise repeat it every tick; `health` reports the missing keys as the `alerts` warning for as long as they are missing. The same applies to the critical alert for a stopped project and to the RECOVERED notice. Find these entries with `log --component health`.

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

It lives in `/opt/boxmunge/logs/boxmunge.log`. The first write of each UTC day moves the previous day's file to `boxmunge.log.YYYY-MM-DD`; 90 days of archives are kept. `logs --boxmunge`, `log` and the health check's 24-hour error count read the archives their window or `--tail` reaches into, so nothing drops out at midnight. Writers take `logs/.boxmunge.log.lock`; if it stays held for 5 seconds the entry is dropped with an error on stderr naming the lock, rather than hanging the command. `health` warns (`operational-log`) if the active file's first line is not a log entry, which stops all logging until the file is moved aside.

A line in a log file that is not a JSON entry (torn by a crash, or hand-edited) is never skipped silently. `log` prints every entry it can read, then a `WARNING: <file>:<line>: ...` on stderr for each torn line, and exits 1, so `--json` output stays parseable and scripts still notice. The MCP `log` tool returns the same warnings and fails, the action API's `oplog.query` fails naming the line, and the health check's `recent-errors` warns, since a torn line may have been an error. Repair or delete the line named.

### Caddy access log

Every site's access log is JSON on the Caddy container's stdout; Caddy's own messages go to its
stderr. Read it as the supervisor user with `docker logs boxmunge-caddy 2>/dev/null` (stdout only).
Docker keeps 5 files of 50 MB (`caddy/compose.yml`). The log has no request or response headers
and no TLS details: it carries the User-Agent as a field of its own and cuts the URI, host, method,
User-Agent and user id to a fixed length, so no client or upstream can make a line long enough to stall CrowdSec. The host's
CrowdSec reads the same stream through the Docker API (`/etc/crowdsec/acquis.d/boxmunge-caddy.yaml`,
stdout only) with boxmunge's parser (`parsers/s01-parse/boxmunge-caddy-logs.yaml`) into the hub's
HTTP scenarios, and never opens a log file Caddy could replace. Every install and upgrade rewrites
those files and CrowdSec's limits drop-in, checks `boxmunge-caddy` belongs to the platform's
`caddy` compose project, restarts CrowdSec, and fails unless CrowdSec tails `boxmunge-caddy` and a
scanner's Caddy line reaches a scenario. Check it with `cscli metrics` (source
`docker:boxmunge-caddy`). `health` (`caddy`) reports an error for a `boxmunge-caddy` from any other
compose project.

A tmpfs at `/var/log/caddy` (up to 320 MB, room for the old configs' own rotation), inside the
container only, lets a rollback to an earlier release (whose site configs write there) still start
Caddy. Nothing reads it, so CrowdSec sees no HTTP traffic until the box is upgraded again; the
rollback's log and alert say so.

Earlier releases wrote `/opt/boxmunge/caddy/logs/access.log`. The upgrade rewrites the
generated log block in `caddy/sites/`, removes `caddy/logs` and CrowdSec's old file entry, and stops
if a `caddy.override.conf` or a hand-placed file in `caddy/sites/` still mentions `/var/log/caddy`:
Caddy no longer mounts it, so that config would stop Caddy from starting. Replace its log block
with the one boxmunge generates, clear the version from the blocklist (`boxmunge-upgrade
clear-blocklist <version>`) and upgrade again.

---

## Backups

Back up a single project (dump, encrypt, store locally). The dump command has 10 minutes
(as does a restore's `restore_command`). Past that the backup fails, the command's process
group is killed inside the container (the error names the group, or says the kill could not be
verified and the command may still be running), and the project lock is released. A dump command
that starts its own session (`setsid`) leaves that group and escapes the kill: keep dump commands
in the foreground. Killing the client side
narrows but does not eliminate server-side lock collisions: a database such as Postgres
notices the dead client only on its next socket I/O, so its locks can outlive the kill briefly. A backup stopped by SIGTERM
(`systemctl stop`, shutdown) cleans up the same way. A plaintext dump left by a process that
could not clean up (SIGKILL, power loss) is removed, and logged, by the project's next backup
or restore:

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
backup service, which ran the `restore_command`, is recreated rather than left running, so an
application that holds its data open (SQLite, say) starts over on the restored files. The
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

`restore` refuses a paused or CVE-quarantined project (`resume` or `security resume` it first). A
project the health monitor stopped gets its data back but stays stopped: only the backup service is
started, for the safety snapshot and the restore, and every service is stopped again afterwards,
whether or not the restore succeeded. Then run `recover myapp`, which starts it on the restored data
and runs the smoke test that clears the stop.

Safety snapshots sit alongside the nightly backups and are pruned by the same retention.

Verify that a backup restores successfully (non-destructive):

```
test-restore myapp
```

---

## Rolling Back

Undo the last deploy -- put back the previous release's code and the data snapshot taken just
before the deploy replaced it:

```
rollback myapp
```

You will be shown the release and the snapshot that will be restored, and asked to confirm before
anything changes (`--yes` skips the prompt).

How it works for a bundle project: every deploy that replaces a release keeps the outgoing code in
`projects/<project>/.releases/previous/`, with `previous.json` recording its bundle name and the
pre-deploy data snapshot. Rollback validates that release again (manifest, identity, compose
hardening), installs it, restores the snapshot, and starts it. Secrets, suppressions, `data/` and
`backups/` are never part of a release, so they are not rolled back. For a promoted staging
release, the previous release is the production release that `promote` replaced. A git project
checks out the commit the last deploy replaced (or the one an open install replaced) and restores
the snapshot taken before that deploy, in the same recorded steps.

A deploy that fails after it started the new release's containers still counts as having replaced
the old one, since production may be running the new code: rollback returns to the release it
replaced, with the snapshot taken just before. Deploying the same release again (a retry) keeps that
pairing, rather than pairing the old release with data the new one may already have changed.

Rollback refuses, with the reason, instead of doing half a rollback:

- after a first deploy, or once a rollback has used the previous release (there is no older release
  to go back to; deploy a known-good bundle instead);
- when the project has backups configured but no snapshot was taken before the last deploy (the
  backup failed or `--no-snapshot` was used), or that snapshot is no longer in `backups/`;
- while an install is open whose pre-deploy hook has not run yet: nothing reached production's
  containers or data, so `prod-deploy <project> --abandon` puts the old files back instead (see
  "An interrupted or failed install").

A project with `backup.type: none` rolls back its code only.

A rollback records each step, so a rerun after a crash carries on where it
stopped. One window remains: if the machine crashes in the seconds after the
snapshot was restored but before that is recorded, the rerun restores the
snapshot again, and anything written to the data in those seconds is lost.

## An interrupted or failed install

Every production install (`prod-deploy`, `rollback`, `promote`, bundle or git) is
recorded in `<project>/.releases/install.json` until it finishes. While it is
open, nothing else starts the project's containers: upgrades, `resume`,
`recover`, container updates, `restore` and `stage` refuse and say why. A
`promote` does not wait: it resumes its own open install, and over another
command's it deploys the staged release as a fix (the last option below).
The alert names your options:

- run the same command again (`prod-deploy <project> --ref <bundle or full SHA>`,
  `rollback <project>` or `promote <project>`): it carries on from where it
  stopped, with the data snapshot it took before it started (once the new
  release's containers may have started, the pre-deploy hook is not run again);
- `prod-deploy <project> --abandon`, while nothing has reached production's
  data: the old release's files go back (a first deploy's code is removed; a
  git project checks the replaced commit out again, and a first git deploy's
  checkout stays, with nothing running it);
  containers and data were never touched, and a staged release stays staged
  and promotable. If it is interrupted, run it again;
- `rollback <project>`, once a pre-deploy hook may have run (this install's,
  or an earlier attempt's it replaced): the old release with the snapshot taken
  before the first attempt;
- or deploy a fix (another bundle or commit, or `promote`): it keeps the same rollback target and
  snapshot, and it can no longer be abandoned once an earlier attempt's hook
  ran. This is also the way out of a first deploy whose hook keeps failing.

While an install is open the health check runs no smoke and takes no critical
action (the install may already have replaced the smoke scripts): `check-all`
reports the project as `WARNING (install open: ...)`, naming these options.

A failure once the containers were started (compose, Caddy or the smoke test)
closes the install as before: production may run the new release, and
`rollback` returns to the old one.

While an install is open, backups use the manifest and compose file of the
release the containers still run, and are skipped with an alert when that is
ambiguous (an attempt may have started its containers). A platform upgrade
leaves the project alone: its configs are not regenerated and it is not
restarted, and the upgrade alerts about it.

If the record no longer matches the files (after a platform rollback, or a hand
edit), it is reported as stale and nothing is resumed automatically: check that
production is what `.releases/live.json` says (for a git project, what `repo/` has checked out), then, as root, run
`boxmunge-server install-txn <project> --drop`. It refuses a record that still
matches the files; use one of the options above for that.

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

Data the containers wrote belongs to their users, so directories you cannot remove yourself are
emptied first by the data helper (the container `stage` copies data with). If that fails,
`project-delete` stops with an error and the project stays registered; run it again once the cause
is fixed. The helper is not used while any container of the project or its staging still exists
(including `compose run` containers and ones a forced delete left behind): the delete then fails,
naming them, until you remove them with `docker rm -f`.

## Service Users After an Upgrade

Projects deployed before boxmunge decided who each service runs as keep running as their images
say; health warns `service-users` for them until each one's next deploy decides (see
PROJECT_CONVENTIONS.md, "Who a service runs as"). That deploy refuses every registry service whose
image runs as root until its manifest declares `security.user`, printing the lines to add. Run
`boxmunge doctor` first: it lists every such service on the box, so you can add them all before
deploying. A `build:` service with no `USER` moves to 10001:10001 at that deploy; if it keeps data
the old user owns, the deploy is refused until `data chown <project> <service> 10001:10001` (or a
`security.user` that keeps the old user).

## Naming an Anonymous Volume

A service that mounts a path with no volume name (`- /var/lib/postgresql/data`, or an image
`VOLUME` no named mount covers) keeps its data in an anonymous volume, which survives only because
Compose hands it from one container to the next; `compose down -v` or a recreate elsewhere loses
it. Give it a name without losing the data:

```
data adopt myapp db:/var/lib/postgresql/data pgdata
```

This stops the service's containers, creates the volume `myapp_pgdata` labelled as Compose labels
its own, copies the anonymous volume into it (owners kept), and starts the containers again. Then
add `pgdata:/var/lib/postgresql/data` to the service's `volumes` (and `pgdata: {}` under top-level
`volumes`) and deploy. To use a `writable.persistent` entry instead, adopt with the name the
platform gives it, `<project>_<entry name>` (`data adopt myapp db:/var/lib/postgresql/data
myapp_pgdata` for an entry named `pgdata`); otherwise the deploy starts on a new, empty volume. The
anonymous volume is left in place; remove it once the service runs on the named one. `data adopt`
refuses a path that is already a named volume, and a target volume that exists with data or without
Compose's labels. If the stop or the copy fails, the new volume is removed and the containers
started again.

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
pause or quarantine that lands while you are answering the prompt, or that finishes just before a
waiting command gets the lock, therefore still wins: `prod-deploy`, `stage`, `promote`, `rollback`,
`restore` and `backup` refuse, and the upgrade restart and health check leave the project alone.
A `promote` holds the one lock across its deploy and the staging teardown that follows it.

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
- Platform upgrades keep it paused: the maintenance page stays in place and the containers stay stopped
- A Docker restart or reboot keeps it stopped: pause sets each container's restart policy to `no` (saving the original), and `resume` restores the originals before starting the containers

The pause is recorded first, so automation leaves the project alone from the start, but it is only
marked complete once the maintenance page is live, the containers are stopped and their restart
policies are held. If a step fails (Caddy cannot reload, `docker compose stop` errors), `pause`
exits 1 with `ERROR: Pausing 'myapp' is incomplete: ...`: the project counts as paused, but may
still be serving or running. Fix the cause and run `pause myapp` again to finish it (an incomplete
pause is the one case where pausing a paused project is accepted), or `resume myapp`. Until then
`status` shows it as `PAUSED (incomplete)`, `health` warns about it under `lifecycle`, and
`container-update` logs that it may still be serving on images it does not update while paused.

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

The styled 503 page is served by Caddy from `/etc/caddy/maintenance` (mounted from `/opt/boxmunge/caddy/maintenance/` on the host). The mount is fixed in `caddy/compose.yml`. Do not hand-edit the Caddy compose file: every `install.sh` run (fresh install or upgrade) replaces it with the bundled one and runs `docker compose up -d`, which recreates Caddy whenever its definition differs from the running container.

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

### Private registry credentials

boxmunge runs Compose without `HOME` or `DOCKER_CONFIG` (see TRUST_MODEL.md, "Compose interpolation"). So the docker CLI reads the registry credentials of the Unix user running the command, found through the password database. What the caller's environment says does not matter:

| Who runs Compose | Credentials used |
|---|---|
| deploy (`deploy`, `stage`, `resume`, `restore`, ...) | `/home/deploy/.docker/config.json` |
| root (the container-update and other timers, upgrades, `sudo boxmunge ...`) | `/root/.docker/config.json` |

A project that pulls from a private registry needs a login for both users. Run these as `supervisor`:

```bash
sudo -u deploy -H docker login registry.example.com
sudo -H docker login registry.example.com
```

A login missing for one user fails noisily ("pull access denied") on that user's runs. Nothing falls back to the other user's file. The two are kept separate on purpose: a single directory shared by both would have to be writable by deploy (buildx keeps state there), and root would then run plugins and credential helpers that deploy could replace.

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

### "start refused" alert

Every start of a project's containers (deploy, stage, upgrade restarts,
container updates, `recover`, `resume`, `security resume`, `restore`)
first re-validates the project's files — the same check deploy runs, over
every profile — checks each bind source without following symlinks, and
confirms every file boxmunge reads (the compose files, the manifest,
`.env`, the generated overlay, and whatever `compose.yml` includes,
extends or names in `env_file`/`label_file`) still hashes to what deploy
recorded. When a check fails, nothing is started or recreated, the running
containers are left alone, and a high-priority alert names the reason. The
alert for one project and reason repeats at most once a day (so a timer
does not page every run); the refusal is logged every time:

- **"has a release staged by boxmunge 0.10.1"** — the project directory
  may hold that stage's files, so production is not recreated from them
  (upgrade restarts, container updates and `security resume` wait with
  this alert; `recover`, `resume`, `restore` and `data adopt` refuse on
  the terminal without one). Running containers keep running. Resolve it with `boxmunge-server legacy-stage <project>`; the
  next run picks it up. This alert does not mean tampering.
- **"an install of <ref> ... is open at phase <phase>"** — a deploy or
  rollback stopped part-way, so the project directory may hold a
  half-installed release. The alert names the options for that phase; see
  "An interrupted or failed install". This alert does not mean tampering.
- **A compose or manifest error** — the files changed since the deploy, or
  this boxmunge release validates more strictly. Fix the file and deploy.
- **"... is a symlink", "is now a file", "does not exist", "is outside the
  project"** — a bind source changed since the deploy. If nobody on the
  box changed it, treat the project as compromised: inspect it as
  `supervisor` before redeploying.
- **"control file ... changed since the project was deployed"** — a file
  boxmunge reads (compose, manifest, `.env`, the overlay, an include or
  env/label file) is not what deploy recorded. A tampered manifest
  (`security.profile: off`) or compose is caught here even when it still
  validates. Redeploy to run the new content.
- **"redeploy to replace it"** — the project's running containers mount
  the project directory, or a file boxmunge reads, read-write (a project
  deployed before this rule). A plain restart would re-run the compromised
  mount; redeploy with the mount made read-only (see SECURITY.md).
- **"was not mounted when the project was last deployed"** or **"no record
  of the bind sources"** — the mounts differ from the last deploy (or the
  project predates the record and no upgrade has run since). Deploy the
  project to start it with its current mounts.

A socket or FIFO an application keeps in a data directory is an allowed
bind source. An in-project symlink used as a bind source is refused
(fail-closed, since a container could repoint it); mount the real path.
A control file that is a symlink staying inside the project (a git
project's `compose.yml` and `manifest.yml` link into `repo/`) is hashed
through its target, so repointing or rewriting it is caught; a control
file linking outside the project is refused.

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

The stop is sticky. Later 5-minute health checks do not run smoke against the stopped project, do not change its recorded failure reason, and do not send more alerts. The daily `container-update` skips it rather than recreating it, and a platform upgrade does not restart it either (the upgrade output lists it under `Not restarted (stopped by the health monitor ...)`). `check-all` reports it as `CRITICAL (stopped by the health monitor ...)`, and `health` lists it under `lifecycle` as `monitor-stopped`. The stop stays in place until you run `recover`, or until a later deploy, rollback, or resume starts the project successfully.

Check the dashboard to confirm the state:

```
status
```

Check logs from just before the containers were stopped:

```
logs myapp --tail 200
```

Once you have identified and fixed the underlying issue, restart the same build with `recover` (no image pull, no rebuild; it restores routing and runs the smoke test). If the fix is restoring data, run `restore` first: it leaves the project stopped for `recover`.

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

Exit codes: 0 = healthy, 1 = warnings, 2 = issues requiring attention. `health` is not run on a
schedule; run it after any change to the box and whenever an alert arrives. A check that cannot run
(for example one that needs root, run from the deploy shell) reports `SKIP`, which does not affect
the exit code. The MCP `health` tool runs the same checks.

| Check | Warns (or errors) when | What to do |
|---|---|---|
| `docker`, `caddy`, `system-container` | Docker, the Caddy container or the boxmunge-system container is not running (error) | `doctor`, then the supervisor user restarts the component |
| `permissions`, `age-key` | the backup key or host secrets have the wrong mode, or the backup key is missing or invalid | fix as the supervisor user |
| `project-containers`, `lifecycle` | a deployed project has no running containers, or is quarantined or stopped by the health monitor | `check <project>`, `logs <project>`, `recover <project>` |
| `config-drift` | a project's Caddy site config differs from what its manifest generates | redeploy the project |
| `recent-errors` | more than 10 errors in the log in the last 24 hours | `log --level error --since 24h` |
| `alerts` | Pushover is not configured, so nothing on this box can alert you | see [Alerts not configured](#alerts-not-configured) |
| `container-updates` | the daily container update failed for a target (also when a service it updates has no container, so its running image is unknown), or has not run for 48 hours | `log --component container-update`; the entry ends with the command's own error output |
| `platform-updates` | a security or break-fix release cannot be installed automatically | see [Upgrading the Platform](#upgrading-the-platform) |
| `docker-userns` | Docker does not remap user namespaces yet, remaps them with another identity, or a source cannot be read on a box boxmunge has not remapped (warning; deploys go on); or the record or `daemon.json` claims boxmunge's remap and a source disagrees, or a remapped box's `caddy/Caddyfile` is not a world-readable regular file (error, alerted once a day) | see [User-namespace remapping](#user-namespace-remapping) |
| `security-profiles` | a service runs with `profile: off` | review the reason in its manifest |
| `cve-scan` | a deployed project has not been scanned for 36 hours, was never scanned, or its last scan was incomplete | `security scan <project>`; see `agent-help cve` |
| `ufw`, `crowdsec`, `aide`, `auditd`, `sysctl` | a host hardening component is off or misconfigured | `doctor`, then the supervisor user |
| `auto-updates` | OS security updates are not being fetched or installed | see [OS security updates](#os-security-updates) |
| `timers` | any boxmunge timer (health, backup, backup-sync, auto-update, container-update, cve-scan) is inactive | the supervisor user runs `systemctl enable --now <timer>` |

Every new check warns rather than errors. `health` exiting 2 during the probation after a platform
upgrade rolls the upgrade back, so only a broken platform reports an error.

### User-namespace remapping

When Docker remaps user namespaces, container uid N is host uid S+N, where S is the start of the
`boxmunge-remap` user's one range of 65536 ids in `/etc/subuid` and `/etc/subgid`. A container's
root is then an unprivileged host user. The box records S in `/opt/boxmunge/config/boxmunge.yml`:

```yaml
userns:
  name: boxmunge-remap
  offset: 1048576
```

Only root writes this record. `docker-userns` (in `health` and `doctor`) checks it against every
other source on each run: `/etc/subuid` and `/etc/subgid` (exactly one range of 65536 at S),
`userns-remap` in `/etc/docker/daemon.json` (`boxmunge-remap:boxmunge-remap`), and the running
daemon (remapped, `overlay2` storage, data root ending in `/S.S`).

- **Freshly installed:** remapped from the first boot. `init-host.sh` creates `boxmunge-remap`
  and its ranges, writes `daemon.json` before Docker first starts, records S, and journals the
  migration as committed, so there is nothing to migrate. Before it changes anything, it refuses a
  host whose Docker already has containers or volumes, and a `daemon.json` it did not write.
- **Not migrated:** a warning. Deploys go on as before.
- **A source cannot be read** (for example a `daemon.json` only root can read) on a box where neither
  the record nor `daemon.json` names `boxmunge-remap`: a warning naming the file. Deploys go on under
  the unremapped rules.
- **Docker already remaps with another identity** (`"userns-remap": "default"` or your own user) and
  the box has no record: a warning. Deploys go on, and the host-namespace rules below apply, because
  the running daemon is remapped. The migration refuses another identity. To use boxmunge's, remove
  `userns-remap` from `daemon.json` and restart Docker as the supervisor user; containers, images and
  volumes made under the old remap stay behind in `/var/lib/docker/<uid>.<gid>/`, so redeploy each
  project (`data adopt` cannot reach them) before you migrate. `"userns-remap": ""` is Docker's
  "off" and counts as not remapped.
- **The record or `daemon.json` claims boxmunge's remap and any source disagrees:** an error naming
  each source, alerted once a day, and the compose validator refuses to deploy until it is fixed,
  because it cannot tell which rules apply. The usual cause is a daemon restarted with another
  `daemon.json`; restore the file and restart Docker as the supervisor user.

On a remapped box, `privileged: true` and `pid`, `network_mode` or `ipc` set to `host` are refused
even under `profile: "off"`: the remapped daemon cannot start such a container. A compose `user:` id
above 65535 is refused there too; before the migration it is a logged warning, and the migration's
check refuses the project until the id is in range.

The boxmunge-system container (age and rclone) runs in the host user namespace
(`userns_mode: host` in `system/compose.yml`) as the deploy user, so it can read the backup key and
write as deploy. On a remapped box (or when the remap state cannot be read), backups, restores,
backup-sync and the `system-container` check in `health` and `doctor` refuse a system container that
runs remapped and print the command that recreates it.

Caddy runs remapped as container root. Its access log goes to its stdout, so no writable bind mount
is needed (see [Caddy access log](#caddy-access-log)). Caddy reads `caddy/Caddyfile` through the
"other" permission bits, so the file is 0644 (`caddy/` itself stays 0750); `docker-userns` reports
an error, with the `chmod`, when it is not.

### Alerts not configured

`alerts` warns when `pushover.user_key` or `pushover.app_token` is missing from
`/opt/boxmunge/config/boxmunge.yml`. Until both are set, health failures, CVE quarantines, failed
container updates, blocked security releases and failing OS updates reach nobody. They are still
logged, and the "Pushover is not configured" log line appears at most once a day. Set the keys as
the supervisor user:

```yaml
pushover:
  user_key: <your user key>
  app_token: <the application token>
```

Then run `test-alert` to confirm a notification arrives.

### OS security updates

`auto-updates` looks for evidence that Debian's unattended upgrades are working, not just that the
service is enabled:

- `/var/lib/apt/periodic/update-stamp` is refreshed only after `apt-get update` succeeds. The check
  warns when it is missing or older than 48 hours. A single broken apt source (for example a
  third-party repository with no release for this Debian version) makes every `apt-get update`
  fail, and no security update is fetched while unattended-upgrades still reports itself active.
- `/var/lib/apt/periodic/upgrade-stamp` is refreshed only after `unattended-upgrade` itself exits
  cleanly. The check warns when it is missing or older than 48 hours. `apt-daily-upgrade.service`
  still reports success when `unattended-upgrade` crashes, so this stamp is the evidence that
  updates are being installed. `/var/log/unattended-upgrades/unattended-upgrades.log` shows why
  it failed.
- On a box set up less than 48 hours ago (by the age of `/etc/apt/apt.conf.d/20auto-upgrades`), a
  stamp that does not exist yet is expected and not reported. A missing `20auto-upgrades` is.
- The last runs of `apt-daily.service` and `apt-daily-upgrade.service` must have succeeded. A
  failure is reported with the unit, its result and exit status.
- `unattended-upgrades` must be active.

Boxes bootstrapped by releases before 0.10.2 got a `50unattended-upgrades` whose origins list
crashed `unattended-upgrade` on every run, so they installed no OS security updates. Upgrading
replaces that file, if it is unedited, with the bundled
`bootstrap/50unattended-upgrades-debian`. The next daily run then installs the backlog and, if a
package needs it, reboots in the maintenance window.

The check never runs `apt-get update` itself. To see the cause, as the supervisor user run
`sudo apt-get update`: the failing source is named in its `E:` and `W:` lines. Fix or remove that
source under `/etc/apt/sources.list.d/` and run `sudo apt-get update` again until it succeeds. A
manual `apt-get update` does not refresh the stamp; the next daily run does, or start it now with
`sudo systemctl start apt-daily.service`. For a failed unit, `journalctl -u <unit>` shows why.

Because `health` is not scheduled, the auto-update timer (every 6 hours) runs the same check. When
it finds a problem it logs a warning (`log --component auto-update`) and sends a priority-1 Pushover
alert, "[<hostname>] OS updates are not being installed". Every boxmunge alert title starts
with the box's hostname. The alert repeats at most once a day while
the same problems persist, and straight away when they change. An alert Pushover did not accept is
retried on the next run. Its state is in `/opt/boxmunge/state/os-updates.json`.

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

Every release is also marked breaking or not. A breaking release changes an
operator workflow, or could make an existing project, manifest, compose file,
command line or upload method fail; it always bumps the minor version, and
its release notes say what to change. Automatic updates may cross minor
lines, but never a breaking release: a 0.10.3 box takes security release
0.11.2 automatically only if neither 0.11.0, 0.11.1 nor 0.11.2 is breaking.
They never cross a major version.

When a security or break-fix release exists that auto-update cannot install
for that reason, the box does not fall behind quietly:

- auto-update logs it as a warning on every run (`log --component auto-update`)
  and sends a priority-1 Pushover alert, for example: "Security release 0.11.2
  cannot be installed automatically: 0.11.0 between this box (0.10.3) and it is
  a breaking release. Read the release notes, then run `upgrade`." The alert
  repeats at most once a day while the same release stays blocked, and
  straight away when a newer one is blocked. An alert Pushover did not accept
  is retried on the next run.
- `health` reports `platform-updates` as `WARN`, naming the release and the
  breaking release (or major version) in the way, until it is installed. It
  is a warning, never an error, so it cannot roll back an upgrade on
  probation.

Read the notes of the breaking release, make the changes they describe, then
run `upgrade`. The state behind both lives in
`/opt/boxmunge/state/platform-updates.json`.

To take security releases only, set this in
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
back to the GitHub releases list, applying the same rules to the markers in
each release's title or notes (`[security]`, `[breakfix]`, `[breaking]`), and
logs a warning.

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

Neither is available from the deploy shell or MCP. `force-target` cannot go below the first
release after 0.10.1: older bundles have no hash-pinned `requirements-mcp.txt`, which every
install needs. It refuses them before downloading anything, without blocklisting.

How an upgrade is applied and undone:

1. The new release is downloaded, its signature and checksum verified, and it is installed
   into the standby venv, built from scratch with every hash-pinned dependency the release
   ships (MCP included); the upgrade needs 250MB free under `/opt/boxmunge`.
   `upgrade --dry-run` runs against it as a pre-flight. If pip cannot install the
   dependencies (a network blip, a full disk), the standby is dropped and a local alert sent.
   The first such failure of a version is not blocklisted or reported, so auto-update retries
   it; a second in a row blocklists it. A successful install and `clear-blocklist` reset the
   count.
2. Platform state is stashed: config, deploy state, and each project's manifest, compose file,
   env files and `boxmunge-scripts/`, with their modes and owners. A git project's
   `manifest.yml` and `compose.yml` links into `repo/` are left out, and a restore never
   touches them (it skips, with a log line, any link an older stash holds). Any other symlink
   among these files stops the upgrade before anything changes, naming each link: replace it
   with the file it points to, or remove it, and retry. A stash that fails, for this or any
   reason, is logged as an error and sends a local alert; the standby venv is dropped and the
   release is not blocklisted, so auto-update retries it once the box is fixed.
3. The venvs swap and `upgrade --apply` first rewrites the latest stash without the symlink
   members an older release wrote, so a rollback's `stash restore` cannot abort on them (a
   failure leaves the stash as it is, sends a high-priority alert and does not stop the
   upgrade). It then migrates manifests and regenerates every project's Caddy site and compose
   overlay, project by project under that project's lock, reloads Caddy and restarts projects.
   Three kinds of project are left exactly as they are (not migrated, regenerated or
   restarted), reported as `LEFT AS IS` or `Skipped (busy)`, alerted, and do not fail the
   upgrade: one with a release staged by boxmunge 0.10.1 (one high-priority alert per project;
   resolve it with `boxmunge-server legacy-stage <project>`; the dry run names it too), one
   with an open install, and one busy with another operation (it keeps its previous configs
   until its next deploy, resume or recover). A bundle project's manifest
   is rewritten at the new schema. A git project's is not: its `manifest.yml` links into
   `repo/`, so it is migrated in memory and you are alerted once to update it in the
   repository (see "Deploying a New Project (Git)"). A failure in any of these
   (a project whose configs cannot be regenerated, a Caddy reload, a project that does not
   restart) fails the upgrade and triggers a rollback.
   A project whose `compose.yml` the new release's compose validator refuses (a file that
   predates a validator fix) does not fail the upgrade. Rolling back would only bring back
   the validator that let the file in. The upgrade gives the project no new overlay or Caddy
   site, and **does not restart or rebuild it**: the upgrade leaves its running containers as
   they were. The upgrade output prints `REFUSED: <project>: <reason>`, the refusal is logged
   as an error (`log <project>`), and one priority-1 Pushover alert lists every refused
   project. Fix the compose file and redeploy. This covers the upgrade only. Other root-run
   operations that recreate containers (the daily container-update, for one) do not consult
   the upgrade's refusal.
   Paused, quarantined and health-monitor-stopped projects are not restarted either; each
   stays offline until `resume`, `security resume` or `recover` brings it back.
4. A health check runs, then a 6-hour probation. A critical health result during probation
   rolls back.

If the upgrade is interrupted (crash, power loss) after the venvs swap but before probation
starts, the next health-timer run rolls back to the previous release and sends a "ROLLBACK"
alert. An interruption is not reported as a release failure. The first one of a version does not
blocklist it, so auto-update retries; a second one does. Promotion and `clear-blocklist` reset the
count. Interrupted before the swap, the previous release simply stays live. A rollback that is
itself interrupted is finished by the next health-timer run.

Before a rollback swaps back, the release being rolled back from tears down every project's
staged release (`boxmunge-server staging-teardown-all --reason platform-rollback`, run by the
shim; an older release does not know `.releases/staged/`) and sends one high-priority alert
per project: "staged release discarded by the platform rollback; re-stage it". A staged release
that an interrupted `promote` still needs is kept, and so is one whose teardown fails or whose
project is busy: the alert says why and names the commands that remove it by hand. If the
teardown itself does not finish (it is stopped after 10 minutes), one high-priority alert names
those commands for every project still holding `.releases/staged/`. It never blocks the
rollback, and the older release ignores what is left.

A rollback swaps the venvs back, restores the stash, and re-runs `upgrade --apply` with the
previous release, so its overlays and Caddy sites are regenerated and projects restarted on
them. Pause and quarantine markers are not restored from the stash: a project you resumed after
the upgrade stays resumed. If either the restore or the re-apply fails, you get a "ROLLBACK
PARTIAL" alert and the shim exits 2; inspect the box as `supervisor`.

Probation ends early, promoting the upgrade, when you deploy, roll back, restore, or run
`backup` yourself. Timer-driven work (the nightly `backup-all`, container-update's
pre-update backup, self-test) does not end it, so container-update keeps waiting until
probation is over.

No other upgrade starts during probation: the standby venv holds the previous release, the
only rollback target. `upgrade --target` and `force-target` refuse with the time probation
ends, without blocklisting anything; `upgrade` and auto-update report the deferral, exit 0
and retry later. To override, an operator ends the probation first (accepting the release on
probation) by removing `/opt/boxmunge/upgrade-state/probation.json`. A `probation.json` that
names the live venv as the previous release (left by an older release's rollback) is stale
and is removed with a warning.

The docs served by `agent-help` (`/opt/boxmunge/docs`) are replaced with the installed
release's on every upgrade, and put back to the previous release's on a rollback, so they
always describe the code that is running.

`upgrade --dry-run` renders every project's migrated manifest and configs in memory and
reports what the upgrade would do. That includes each project the new release's compose
validator would refuse, as `<project>: would be refused by this release's compose validator
... : <reason>`. A refusal does not fail the dry run, because it does not fail the upgrade.
The dry run writes nothing and sends no alert. The upgrade shim runs it as a pre-flight check
against the new release before touching anything, so `upgrade --dry-run` run by hand
reports against the installed release.

## Upgrading from 0.10.1 with a release staged

Unstage before upgrading. If a project still has a release staged by 0.10.1,
the upgrade leaves it exactly as it is: the dry run says "<p>: a release
staged by boxmunge 0.10.1 (<kind>) will be left as is; after the upgrade,
resolve it with boxmunge-server legacy-stage <p>", the apply alerts once,
and the health check alerts again at most once a day until it is resolved. The project keeps running its current containers
and is backed up; starts, deploys and pause are refused, quarantine is held,
and health smoke checks are suspended.

Run `boxmunge-server legacy-stage <p>` to see what production runs (this works
during probation too). Once probation has ended, run `--discard` (put production's release back; with
`--confirm-recreated` if production was already started from the staged files)
or `--keep-staged` (treat the staged release as promoted). If it is
interrupted, run the same command again.

`legacy-stage` is operator-only: run it as root (`sudo boxmunge-server legacy-stage <p>`); the
deploy shell and MCP do not offer it. It takes the project's lock (if the project is busy, try
again). `--discard` and `--keep-staged` refuse while a platform rollback is still possible:
during probation (it says when probation ends) or while an interrupted upgrade or rollback is
pending. They also refuse while a platform upgrade is running ("a platform upgrade is in
progress; run it again after it finishes"): from its stash to its swap there is no probation yet,
but a rollback would still restore that stash. A `probation.json` it cannot read refuses too,
naming the file to fix or remove. With no flag it works in all of these cases; except during an
upgrade it adds "Not available yet: <why>".
For a git project it runs git as the deploy user, so `repo/` must be deploy's: one cloned with
`sudo` is refused with the fix (`chown -R deploy:deploy <p>/repo`, then retry).

- With no flag it prints the evidence and the choices it allows, and changes nothing. The
  evidence is when the stage was made, the deploy state's ref, the staged ref, production's
  release, and whether production's containers are `untouched` (all created before the stage)
  or `recreated` (started from the staged files: a failed 0.10.1 promote, or a recreate during
  the stage). A git stage that changed no code (no `--ref`, or the deployed commit) is
  `untouched` without that time ("not needed: the stage changed no code"), so `repo/`'s reflog
  is not read. A `leftover` (a 0.10.1 promote whose unstage did not finish) has no evidence and
  allows only `--discard`.
- `--discard` throws the staged release away, puts production's release back and recreates
  production from it on this release's overlay. For `untouched` and `leftover`, production keeps
  the release it runs. For `recreated` it also needs `--confirm-recreated`: discarding the staged
  files changes what runs, and data the staged code wrote stays (it names the newest pre-deploy
  snapshot for a manual `restore`).
- `--keep-staged` treats the staged release as promoted. For `untouched` it first takes a
  pre-deploy snapshot with production's manifest; for `recreated`, `rollback` uses the newest
  pre-deploy snapshot taken after the stage; with none, `rollback` refuses ("no pre-deploy data
  snapshot was taken when that release was replaced ...").

The choice is recorded first, and a rerun must name the same one. The command then stops staging,
removes the staging site, puts the code in place, cleans up the staging files, drops the stage
record (last), and finishes what the upgrade skipped: manifest migration, config regeneration and
a start of production. It alerts once the stage is resolved. It never touches the stash.

An install left open by an interrupted deploy (see "An interrupted or failed install") is also
left as is by the upgrade. A record that no longer matches the files, after a platform rollback to
0.10.1 and a redeploy by it, is reported as stale; check production, then drop it as root with
`boxmunge-server install-txn <project> --drop`.


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

- Daily between 03:00 and 03:30 via `boxmunge-cve-scan.timer`
- Not yet at deploy or image-update time: run `security scan <project>`
  after a deploy to check a new image at once
- Ad-hoc:

  ```
  boxmunge security scan              # all projects
  boxmunge security scan myapp        # one project
  # exit 0 clean, 2 quarantined/at-risk, 1 a project failed or was only
  # partly scanned (also sent as one priority-1 alert per run)
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
level finding still applies or if any image could not be scanned.

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

The server's `mcp` package is part of every install. `install.sh` and every platform upgrade
(manual or auto-update) install it into the new environment from the release's hash-pinned
`requirements-mcp.txt`, together with the other dependencies, so it survives upgrades. An upgrade
whose bundle lacks that file, or whose MCP install fails, stops at pre-flight with the current
release still live, like any other dependency failure.

If the package is missing anyway, `mcp-serve` exits 1 and `doctor` fails its "MCP package
installed" check, both with the repair: as root, re-run the installer of the installed release
(`sudo bash boxmunge-install.sh`, from that version's GitHub release). Do not `pip install` it
by hand: that is unpinned, and the next upgrade builds a fresh environment without it. The
first upgrade from 0.10.1 or earlier is run by that release's upgrade shim, which does not
install MCP; the upgrade after it does, or re-run the installer to have it now.

Note: `boxmunge` on PyPI is the *client* CLI. The server package is
`boxmunge-server` and is installed from GitHub releases, not PyPI.
