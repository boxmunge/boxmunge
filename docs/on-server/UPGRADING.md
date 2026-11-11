# Upgrading from 0.9 or 0.10

This page is for you if you run your own boxmunge box and it is still on a 0.9 or 0.10
release. It takes you to 0.11, step by step. Your sites stay up: the upgrade restarts each
project once, and leaves running anything it cannot handle yet.

Every command here was run on a test box upgraded from 0.9.1, 0.9.16 and 0.10.1. The few
that come from the code instead are marked so.

Run commands marked `deploy>` in the deploy shell (`ssh -p 922 deploy@your-box`, then type
the command), and commands starting with `sudo` as `supervisor` (`ssh -p 922
supervisor@your-box`).

## Why your box is stuck

Two releases since 0.10.0 are breaking releases (0.10.1 and 0.11.0). They change things that
can make an existing project or workflow fail, so auto-update never installs them, or
anything after them. It also never tells you so on 0.9 or 0.10 (the alert for a blocked update
arrived in 0.11.0). The box just stays where it is.

See which release you are on:

```
deploy> version
boxmunge 0.10.1
```

See what auto-update has been saying (it runs every 6 hours, if you enabled it):

```
sudo journalctl -u boxmunge-auto-update --since -7d --no-pager | tail
```

On 0.9 and 0.10.0 it prints `No security updates available.` and on 0.10.1
`No security and break-fix updates available.` (these two lines are from the code; the
rehearsal ran the command on 0.11). That's correct, even though newer releases exist: none
of them can be installed without crossing a breaking release.

## Which release to upgrade to

Upgrade to **0.11.6**, the bridge release. From 0.11.7 on, a release refuses to be installed
over anything older than 0.11.0, so a 0.9 or 0.10 box goes to 0.11.6 first.

| Your box | Upgrade to |
|---|---|
| 0.7.0 to 0.10.1 | 0.11.6 |
| older than 0.7.0 | ask for help first (see the end of this page) |
| 0.11.0 or later | this page is not for you: run `upgrade` |

Once you are on 0.11.6, `upgrade` (or auto-update) takes you the rest of the way.

**0.7.0 to 0.9.1:** 0.11.6 is also the only 0.11 release you can install. The upgrader those
releases installed checks every new release in a way that 0.9.1 to 0.11.5 fail
(`Pre-flight FAILED: import test`). 0.11.6 passes that check.

### If you targeted 0.11.7 or later

The new release refuses before anything on the box changes. What it prints depends on the
release you are on (these lines are from the test that runs each old upgrader against 0.11.7;
the rehearsal did not cover them). On 0.9.2 to 0.10.1:

```
  ERROR: boxmunge 0.11.7 cannot be installed over 0.10.1: an upgrade must start from 0.11.0 or later. Upgrade to 0.11.6 first: sudo /opt/boxmunge/bin/boxmunge-upgrade target 0.11.6
  This box stays on 0.10.1. The upgrader blocklists 0.11.7 on this box after this refusal; that does not stop the upgrade to 0.11.6. Once the box runs 0.11.6, clear it before upgrading further: sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist 0.11.7
... boxmunge-upgrade: Pre-flight FAILED: dry-run upgrade
```

On 0.7.0 to 0.9.1:

```
Traceback (most recent call last):
  ...
AttributeError: module 'boxmunge' has no attribute '__version__'. Only the upgrader of a release before 0.9.2 reads it, and boxmunge 0.11.7 cannot be installed over one: an upgrade must start from 0.11.0 or later. Upgrade to 0.11.6 first: sudo /opt/boxmunge/bin/boxmunge-upgrade target 0.11.6
  The upgrader blocklists 0.11.7 on this box after this refusal; that does not stop the upgrade to 0.11.6. Once the box runs 0.11.6, clear it before upgrading further: sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist 0.11.7
... boxmunge-upgrade: Pre-flight FAILED: import test
```

Your box stays on its release, with its own upgrader, and your projects are not touched. The
release you targeted is now blocklisted on the box. That does not stop 0.11.6: carry on with
this page and target 0.11.6. Once the box runs 0.11.6, clear the entry (with the release
you targeted in place of 0.11.7), or the box will keep skipping that release:

```
sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist 0.11.7
```

In the rest of this page, `0.11.x` means 0.11.6.

## Before you upgrade

None of these checks change anything, apart from the backup in step 1. Work through all of
them first: most problems are much easier to fix before the upgrade than after.

### 1. Take a backup and check it

For each project:

```
deploy> backup myapp
deploy> test-restore myapp
```

`test-restore` must print `PASS: Backup decrypts successfully`. Copy
`/opt/boxmunge/config/backup.key` somewhere off the box too: no backup can be restored
without it.

**On 0.9, backups may have been failing all along.** If `backup` prints
`age: error: failed to open input file ... permission denied`, your box has this 0.9 bug:
backups fail whenever the `deploy` user's uid isn't 1000 (`id -u deploy` shows it). It is
fixed from 0.10.1 onward. Make a plain copy instead, then copy the folder off the box:

```
sudo bash -c 'set -e; d=/root/before-upgrade; mkdir -p $d
tar -C /opt/boxmunge -czf $d/boxmunge-projects-config.tgz projects config
for v in $(docker volume ls -q); do
  docker run --rm -v "$v":/v:ro -v $d:/out busybox:1.36 tar -czf "/out/volume-$v.tgz" -C /v .
done; ls -la $d'
```

This copies files as they are. A database's files copied while it runs may not restore
cleanly, so for a database also keep a dump made with its own tool (`pg_dump`, for example).
The folder holds secrets: `config/backup.key` and every project's `secrets.env`. Keep it as
safe as you keep `backup.key`.

### 2. Make sure everyone can log in with a key

0.11 turns SSH into key-only logins for everyone: no passwords, no keyboard-interactive
(one-time codes). Someone who logs in with a password today can't log in after the upgrade.
Sessions that are already open stay open.

See what sshd allows now:

```
sudo sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|authenticationmethods|allowusers) '
sudo grep -rniE '^\s*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|AuthenticationMethods|Match)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
sudo journalctl -u ssh --since -30d --no-pager | grep -E 'Accepted (password|keyboard-interactive)'
```

- If the first command shows `passwordauthentication yes`, or the last one lists logins,
  someone uses a password. Before you upgrade, give them a key: they run
  `ssh-keygen -t ed25519` on their own computer and send you the `.pub` file, which you add
  to their `~/.ssh/authorized_keys` on the box. Then they log in once with it to check. By
  default only `deploy` and `supervisor` can log in at all (`allowusers`).
- If any line sets `AuthenticationMethods` with `keyboard-interactive` (two-factor codes),
  remove it and use hardware-backed keys instead (`ssh-keygen -t ed25519-sk`). Otherwise the
  upgrade stops with:

  ```
  ERROR: sshd rejects its configuration with /etc/ssh/sshd_config.d/00-boxmunge.conf in place:
  Disabled method "keyboard-interactive" in AuthenticationMethods list "publickey,keyboard-interactive"
  AuthenticationMethods cannot be satisfied by enabled authentication methods
  ```

  (see "If the upgrade stops" below).

Check that `supervisor` and `deploy` each have a key:

```
sudo bash -c 'for u in supervisor deploy; do h=$(getent passwd $u | cut -d: -f6); printf "%s: " $u; grep -cE "^(ssh|ecdsa|sk-)" $h/.ssh/authorized_keys 2>/dev/null || echo 0; done'
```

Each must show at least `1`.

### 3. Finish every staged release

```
sudo bash -c 'ls -d /opt/boxmunge/projects/*/compose.staging-base.yml /opt/boxmunge/projects/*/compose.boxmunge-staging.yml /opt/boxmunge/projects/*/.releases/prestage 2>/dev/null; ls /opt/boxmunge/state/staging/ 2>/dev/null; docker ps -a --format "{{.Label \"com.docker.compose.project\"}}" | sort -u | grep -- "-staging$" || echo "no staging containers"'
```

If it prints any staging file, or a `<project>-staging` name, that project has a release
staged. (`state/staging/` keeps a file for every project that was ever staged: those alone
mean nothing.)

- **On 0.9 and 0.10.0: you must finish it before upgrading.** On these releases, `stage`
  writes the staged release's files over production's, and `unstage` does not put them back.
  To keep the staged release, run `promote myapp`. To throw it away, run `unstage myapp`,
  then deploy the release production should run again: upload its bundle and run
  `prod-deploy myapp`. Only that sequence leaves production's files as they should be. A
  stage from these releases left in place is misread by the upgrade (see "LEFT AS IS"
  below).
- **On 0.10.1:** run `promote myapp` or `unstage myapp`. If you leave it, the upgrade leaves
  that project as it is and you resolve it afterwards with `legacy-stage` (see below).

Folders whose names end in `-staging` inside a project, such as `data-staging`, are
staging's old copies of data. They are harmless and can stay:

```
sudo find /opt/boxmunge/projects -mindepth 2 -maxdepth 4 -name '*-staging' -not -path '*/backups/*'
```

A whole project named `<something>-staging` is different. That name is reserved from 0.10.1
on, so the upgrade skips that project and reports it. Ask for help if you have one
(`ls -d /opt/boxmunge/projects/*-staging`).

### 4. Look for compose settings 0.11 refuses

```
sudo grep -nE '^\s*(container_name|ports):' /opt/boxmunge/projects/*/compose.yml
sudo grep -l /var/log/caddy /opt/boxmunge/projects/*/caddy.override.conf
```

- `container_name:` is refused. Remove the line, and refer to that service by its service
  name instead.
- `ports:` is refused unless the manifest declares the port under `security.published_ports`
  (from the code: see PROJECT_CONVENTIONS.md and SECURITY.md, "Published ports").
- A project `caddy.override.conf` that writes a log under `/var/log/caddy` stops the
  upgrade. Replace its log block (OPERATIONS.md, "Caddy access log"). No output, or
  `No such file or directory`, means you have none. The site files boxmunge generates
  itself in `caddy/sites/` are rewritten for you.

You can fix these after the upgrade instead. Such a project keeps running as it is, but it
is not restarted (`REFUSED`, below) until you fix it and redeploy.

### 5. Disk, Docker, Compose and Python

```
df -h /opt/boxmunge /var/lib/docker
docker version --format '{{.Server.Version}}'
docker compose version --short
python3 --version
```

- **Disk:** the upgrade needs 250 MB free under `/opt/boxmunge`, plus room in
  `/var/lib/docker` to rebuild boxmunge's own image.
- **Docker Compose:** 2.35.0 or newer. An older one stops the upgrade with
  `ERROR: Docker Compose 2.34.0 is older than 2.35.0, ... Upgrade it: apt-get install --only-upgrade docker-compose-plugin`.
  Run that (`sudo apt-get install --only-upgrade docker-compose-plugin`) before you upgrade.
  (The rehearsal tested the refusal, not this apt command.)
- **Python:** 3.11 or newer. Debian 13 ships 3.13. If yours is older, ask for help: it means
  an OS upgrade first.

### 6. No upgrade in progress

```
sudo bash -c 'ls /opt/boxmunge/upgrade-state/; cat /opt/boxmunge/upgrade-state/blocklist.json'
```

There must be no `probation.json`. The blocklist should be `{}`. If it lists the release
you are about to install, clear it once you have fixed the cause:
`sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist 0.11.x`.

### 7. boxmunge's own checks

```
deploy> doctor
deploy> health
deploy> status
```

Fix anything that fails before you go on. Warnings about Pushover or off-box backups not
being configured are fine. Don't rely on `upgrade --dry-run` on 0.9 or 0.10: it checks
your current release, not 0.11. The real preview runs at the start of the upgrade itself.

## Upgrade

Pick a quiet time: each project restarts once. In the rehearsal the upgrade took about two
minutes. A dropped SSH connection would kill the upgrade part-way, so start it with `nohup`
(part of Debian's coreutils, so always there), writing to a log file, and follow that file:

```
sudo nohup /opt/boxmunge/bin/boxmunge-upgrade target 0.11.x >> ~/upgrade-to-0.11.log 2>&1 &
tail -f ~/upgrade-to-0.11.log
```

Writing to the file rather than piping through `tee` matters: if the connection dropped, a
dying `tee` would take the upgrade with it. Stop `tail` with Ctrl-C once you see the last
line below; the upgrade keeps running if the connection drops. (The rehearsal ran the
command in the foreground, in a session that was never dropped.)

What it prints, in order:

1. The download, `Cosign signature on SHA256SUMS verified`, and the checksum `OK`.
2. `Running pre-flight checks...` and a preview from the new release. Each project gets
   one or more lines: `configs render OK`, `would be refused by this release's compose
   validator ...`, or `a release staged by boxmunge 0.10.1 (...) will be left as is`. None of
   these stop the upgrade. Then `Pre-flight passed`.
3. The system upgrade (Caddy and boxmunge's system container are recreated, the sshd
   settings are installed), then `boxmunge 0.11.x installed successfully`.
4. `Applying upgrade...` with a summary per project: `Restarted:`, `REFUSED:`,
   `LEFT AS IS:`, `Not restarted (...)`.
5. Last: `Upgrade to 0.11.x complete, probation started`.

Lines such as `Caddyfile input is not formatted` and Perl locale warnings are harmless.

## After the upgrade

```
deploy> version
deploy> doctor
deploy> health
deploy> check-all
deploy> status
deploy> log --tail 60
```

`version` shows the new release. Then check each site in a browser.

### Warnings you should expect

- `upgrade-probation -- 0.11.x on probation until <time>`: see "Probation" below.
- `service-users -- users not decided for ...`, and in `doctor`, `Service users declared` with
  a list of services: see "Redeploy each project" below.
- `docker-userns -- userns remapping is off`: an optional migration, described in
  OPERATIONS.md ("Migrating an existing box"). It's not needed for this upgrade.
- `cve-scan -- ... never scanned`: clears after the nightly scan.
- `alerts -- Pushover is not configured`: boxmunge can't alert you until you set it up
  (OPERATIONS.md, "Alerts not configured"). From 0.11 on, it is how the box tells you about
  updates it cannot install.

### What the upgrade's lines mean

- **`REFUSED: myapp: <reason>`.** The new release refuses something in that project's
  `compose.yml`, `container_name` for example. The project keeps running its existing
  containers but was not restarted. Fix what the reason names, then redeploy the project.
- **`LEFT AS IS: myapp: a release staged by boxmunge 0.10.1 (bundle)`** (or `(git)`). A
  stage was still in place. The project keeps running and is backed up, but deploys, stages
  and restarts are refused until you resolve it. After probation (it refuses before then):

  ```
  sudo boxmunge-server legacy-stage myapp            # shows what production runs, changes nothing
  sudo boxmunge-server legacy-stage myapp --discard  # drop the staged release, keep production's
  ```

  `--keep-staged` is the other choice: it treats the staged release as promoted.
- **`LEFT AS IS: ... (leftover)` on a box that was on 0.9 or 0.10.0.** This is a stage from
  one of those releases, and 0.11.5's `legacy-stage` misreads it. It says production runs
  "the release a 0.10.1 promote installed" and offers only `--discard`. But `--discard`
  starts the *staged* release in production. If you meant to keep the staged release,
  `--discard` gives you that. If not, run it and then straight away `prod-deploy myapp` with
  production's bundle, which puts production's release back. This is why step 3 says to
  finish these stages first.

  From 0.11.6 on, such a stage shows as
  `a release staged by a boxmunge release before 0.10.1 (pre0101)`. There, `--discard` stops
  staging and starts nothing. Production keeps running its release, but every start of the
  project is refused until you upload production's bundle and `prod-deploy myapp`.
- **`named the images myapp's containers run: myapp's web image, built on this box`.**
  Informational: 0.11 renames the images it builds (to `boxmunge.invalid/myapp/web`; the
  entry's detail lists the names).

### Probation

For six hours after the upgrade the box watches its own health. A new health error makes it
roll back to your old release on its own (see below). During probation:

- `legacy-stage` waits for probation to end.
- A deploy, rollback, restore or `backup` ends probation early and keeps the new release,
  so from then on nothing rolls back automatically. The upgrade log shows
  `Probation ended early: user interaction (deploy)`.

Unless something needs fixing now, leave the box alone for the six hours. `health` shows
when probation ends.

### Redeploy each project

From 0.11, every deploy decides which user each service runs as. Your projects keep running
as they are until their next deploy, and that deploy may ask for changes first. `doctor`
lists the services that will need them.

- **A registry image that runs as root** (postgres, nginx, busybox, most images without a
  `USER`): the deploy refuses and prints the lines to add to `manifest.yml`, for example:

  ```yaml
  schema_version: 2      # or later; needed for a security block
  services:
    db:
      security:
        user: image
        reason: "postgres entrypoint drops privileges"
  ```

  `user: root` also needs a `reason`. A service that is only in `compose.yml` (a database,
  say) needs a manifest entry holding only that `security` block.
- **A service you build** (`build:` in compose) with no `USER` runs as uid 10001 from now on.
  If its data belongs to the old user (root), the deploy refuses with
  `... keeps data in /opt/boxmunge/projects/myapp/data that the old user owns ... or run
  boxmunge data chown myapp web 10001:10001 before deploying again`. Do what it says, then
  deploy:

  ```
  deploy> data chown myapp web 10001:10001
  deploy> prod-deploy myapp --redeploy
  ```

  `data chown` takes a backup first and stops the service until the deploy. (In the
  rehearsal, the deploy after it used a newly uploaded bundle. `--redeploy` is what
  `data chown` itself suggests.)
- **Postgres backups:** if your manifest uses `pg_dump -U ...` / `psql -U ...`, change
  them to `pg_dump --clean --if-exists -U <user> <db>` and
  `psql -v ON_ERROR_STOP=1 --single-transaction -U <user> <db>`, then take a fresh backup.
  A restore with the old pair leaves current data in place.

Once every project has been deployed and probation is over, take a fresh backup of each
(`backup myapp`, then `test-restore myapp`).

### Keep going

You are now on 0.11. `upgrade` installs the newest release when you choose to, and
auto-update installs security and break-fix releases by itself.

## If the upgrade stops

**It stopped before switching over.** Your box is still on the old release and your
projects keep running. You see an error and then, for example:

```
ERROR: install.sh failed (exit 1); aborting upgrade before slot swap
```

Parts of the system may already be updated. The upgrader itself always is: the old one
replaces itself before it runs the new release's installer. Caddy and boxmunge's system
container are replaced only if that installer got past its first checks: Python and Docker
Compose are checked first, so with an old Compose (step 5) nothing else has changed; the
sshd check comes last, so after the sshd error (step 2) Caddy and the system container are
already the new ones. Either way that's expected, and the retry finishes the job. The
release is now blocklisted on your box, so running the same command again prints:

```
FATAL: Version 0.11.x is blocklisted on this box (it failed an earlier upgrade). To override, run as supervisor: sudo /opt/boxmunge/bin/boxmunge-upgrade force-target 0.11.x
```

Don't use `force-target`. Fix what the error named (the sshd lines from step 2, Compose from
step 5, and so on), then:

```
sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist 0.11.x
sudo nohup /opt/boxmunge/bin/boxmunge-upgrade target 0.11.x >> ~/upgrade-to-0.11.log 2>&1 &
tail -f ~/upgrade-to-0.11.log
```

On 0.9, if the upgrade stopped early (during the download or the pre-flight), the old
upgrader is still in place. Running `target` again then prints only
`Version 0.11.x is blocklisted, skipping` and exits without doing anything. Clear the
blocklist as above. (From the code: the rehearsal's 0.9 failures were all later than that.)

**It rolled back during probation.** You see:

```
boxmunge-upgrade: New health errors since the upgrade: <check>
boxmunge-upgrade: CRITICAL: 0.11.x failed its probation health check during probation — rolling back
...
boxmunge-upgrade: Rollback complete: reverted to boxmunge 0.10.1
```

The box is back on your old release, and your projects run as they did. Find out why the
health check failed (`deploy> health`, and `deploy> log --tail 60`), fix it, then clear the
blocklist and run the upgrade again, as above.

**`Rollback PARTIAL`.** The rollback switched back to your old release, but could not
re-apply it. In the rehearsal that happened when Caddy was not running:
`ERROR: upgrade failed: Caddy reload failed: Caddy is not running ...`. Fix what it names,
then re-apply the old release and check:

```
sudo docker start boxmunge-caddy     # the fix in that case
sudo boxmunge-server upgrade --apply
deploy> doctor
```

## Getting help

Send these, as text. Every command is read-only.

```
deploy> version
deploy> doctor
deploy> health
deploy> status
deploy> log --tail 100
deploy> log --component upgrade --tail 50
sudo cat /opt/boxmunge/upgrade-state/blocklist.json
sudo journalctl -u boxmunge-auto-update --since -7d --no-pager | tail -20
```

Also send the upgrade's own output (`~/upgrade-to-0.11.log`) and any alert you received.

Before sending, remove anything secret. Never send `config/backup.key`, a project's
`secrets.env`, or the Pushover tokens in `config/boxmunge.yml`. Replace your hostnames and
IP addresses if you'd rather not share them.
