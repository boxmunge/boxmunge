# SPDX-License-Identifier: Apache-2.0
"""Static per-command usage text.

`help <command>`, `<command> --help` and every usage error print from this
table, so showing help never needs to call a command's handler. Each entry
must describe exactly the arguments the handler accepts; the handler rejects
anything else. A test keeps the keys in step with `cli.COMMANDS`.
"""

USAGE: dict[str, str] = {
    "help": """\
Usage: boxmunge help [command]

Show the command overview, or the usage of one command. Never runs the
command.""",
    "agent-help": """\
Usage: boxmunge agent-help [topic]

AI agent orientation. Topics: architecture, operations, conventions, rules,
security, cve, cve-incident, writable, images.""",
    "init-host": """\
Usage: boxmunge init-host

Not a server command. Host provisioning is done once, as root, by
bootstrap/init-host.sh (or `boxmunge server-setup` from the client).""",
    "version": """\
Usage: boxmunge version

Show the installed boxmunge version.""",
    "doctor": """\
Usage: boxmunge doctor [--json]

Verify host health and configuration. Read-only.""",
    "status": """\
Usage: boxmunge status [--json]

Dashboard of all projects: status, last check, deployed-at. Read-only.
Exits 1 if any project's state could not be read (shown as ERROR).""",
    "health": """\
Usage: boxmunge health [--json]

Run platform-wide health checks. Read-only.""",
    "self-test": """\
Usage: boxmunge self-test [--json]

Deploy the canary project and verify the platform end to end.""",
    "handshake": """\
Usage: boxmunge handshake

Print server version and client compatibility info as JSON.""",
    "test-alert": """\
Usage: boxmunge test-alert

Send a test Pushover notification.""",
    "add-git-project": """\
Usage: boxmunge add-git-project <name> <repo-url> [--ref REF]

Register a git-backed project.""",
    "stage": """\
Usage: boxmunge stage <project> [--ref REF] [--no-pull] [--dry-run]

Deploy alongside production on the staging hostname for verification.
Build services are built on their base images' current registry digests;
--no-pull builds from the base images in this box's local image store.""",
    "promote": """\
Usage: boxmunge promote <project> [--no-pull] [--dry-run]

Promote the staged build to production. Build services are built again on
their base images' current registry digests: normally the ones the stage
pulled, so the build is cached. A base image that moved since the stage
reaches production untested; stage again to test it. --no-pull builds from
the base images in this box's local image store, which can be older than
the stage's.""",
    "unstage": """\
Usage: boxmunge unstage <project> [--dry-run]

Tear down staging.""",
    "prod-deploy": """\
Usage: boxmunge prod-deploy <project> [--ref REF] [--no-snapshot] [--no-pull] [--dry-run]
                                     [--accept-stale-kev]
       boxmunge prod-deploy <project> --redeploy [--no-snapshot] [--no-pull] [--dry-run]
                                     [--accept-stale-kev]
       boxmunge prod-deploy <project> --abandon

Deploy directly to production (skips staging). Build services are built on
their base images' current registry digests; --no-pull builds from the base
images in this box's local image store. With no new bundle in the inbox,
prod-deploy refuses; --redeploy deploys the installed release again (as
strictly checked as a new deploy).
--abandon undoes an install that stopped before its pre-deploy hook ran:
the replaced release's files go back; containers and data are not touched.
--accept-stale-kev lets a CVE-quarantined project's fix through although
there is no usable CISA KEV catalog; it is logged and alerted. It never
overrides a stale catalog that lists a CVE still in the release's images.""",
    "install-txn": """\
Usage: boxmunge install-txn <project> --drop

Remove a stale install record (.releases/install.json): one the files no
longer match, after a platform rollback or a hand edit, or one that cannot
be read. Check first that production is what .releases/live.json says. A
record that still matches is refused: rerun, --abandon, rollback or deploy
a fix instead. Operator-only: run it as root, as boxmunge-server.""",
    "legacy-stage": """\
Usage: boxmunge legacy-stage <project> [--discard [--confirm-recreated] | --keep-staged]

Resolve a release staged by boxmunge 0.10.1 before this upgrade. Without a
flag, shows what production runs and the choices, and changes nothing.
--discard throws the staged release away and puts production's back (with
--confirm-recreated when production was already started from the staged
files); --keep-staged treats it as promoted. A stage made before 0.10.1
(pre0101) wrote over production's files and kept no copy: its --discard
stops staging and starts nothing, and every start is refused until a
prod-deploy of production's release (or a stage and promote of the staged
one, which needs no copy_data: production's data stays where it is).
Refused while a platform rollback is
still possible (probation). If interrupted, run the same command again.
Operator-only: run it as root, as boxmunge-server.""",
    "staging-teardown-all": """\
Usage: boxmunge staging-teardown-all --reason platform-rollback

Tear down every project's staged release and alert to re-stage it. Run by
the upgrade shim before a platform rollback swaps back (an older release
does not know the staged slot); a failure is alerted with that project's
manual commands and never blocks the rollback. Operator-only: run as root.""",
    "rollback": """\
Usage: boxmunge rollback <project> [--yes]

Restore the previous deployment. Does not support --dry-run.""",
    "pause": """\
Usage: boxmunge pause <project> [--reason TEXT] [--no-snapshot] [--yes]

Take a project offline behind a styled maintenance page. A data snapshot is
taken first (the pre-deploy snapshot of a deploy that ends the pause);
--no-snapshot pauses without one. Does not support --dry-run.""",
    "resume": """\
Usage: boxmunge resume <project> [--skip-security-checks] [--yes]
       boxmunge resume <project> --no-start

Bring a paused project back online (pulls latest images first). Does not
support --dry-run. --no-start starts nothing: the project stays down behind
its maintenance page until the next prod-deploy, promote or rollback starts it, which
ends the pause (for a project resume refuses to start and only a deploy can
repair).""",
    "recover": """\
Usage: boxmunge recover <project> [--yes]

Restart a production stack the health monitor stopped (same build). Does not
support --dry-run.""",
    "diff": """\
Usage: boxmunge diff <project> [--ref REF]

Preview what a deploy would change. Read-only.""",
    "project-add": """\
Usage: boxmunge project-add <name>

Register a project name in the allowlist.""",
    "project-list": """\
Usage: boxmunge project-list [--json]

List registered project names.""",
    "project-forget": """\
Usage: boxmunge project-forget <project>

Drop a registry entry whose project directory is gone (a removal that did
not finish): the name leaves the registry and its leftover state files are
deleted. Refused while the project directory or any container of the
project exists; use project-delete then. Operator-only: run it as root, as
boxmunge-server.""",
    "project-delete": """\
Usage: boxmunge project-delete <project> [--yes] [--force]

Destructive: stop the project, remove its files, and deregister it. Asks for
confirmation unless --yes. If container teardown fails, nothing is deleted
and the command exits 1; --force deletes anyway. Does not support --dry-run.""",
    "data": """\
Usage: boxmunge data adopt <project> <service>:<path> <name>
       boxmunge data chown <project> <service> <uid>:<gid> [--no-snapshot | --staging]

adopt copies the service's anonymous volume at <path> into a new named volume
<project>_<name> that the next deploy adopts. Stops the service's containers
for the copy and starts them again. Then add <name>:<path> to the service's
volumes and <name>: {} to the top-level volumes, and deploy (for a
writable.persistent entry instead, adopt as <project>_<entry name>). A deploy
refused for this leaves its install open: prod-deploy <project> --abandon
first. The anonymous volume is kept until you remove it.

chown first takes the project's backup snapshot (kind prechown) while the
service still runs (when the backup service is stopped, the dump runs over
its data at rest in a one-off container of its image, offline), then stops
the service, gives its read-write binds and named volumes, and staging's
copies of them, to <uid>:<gid>, records the user and regenerates the
overlay, and leaves it stopped (its restart policy held) until you deploy,
which runs it as that user. When the service is the backup service, that deploy
uses the snapshot as its pre-deploy snapshot (its own dump could not run)
while Docker shows the service has not run since, so its rollback restores
the data from before the change; a rollback does not revert the ownership.
A failed snapshot refuses and changes nothing. --no-snapshot goes on without
one: a rollback of the next deploy then cannot restore data. A project with
backup.type: none has no snapshot to take, and says so. --staging gives
staging's copies alone to <uid>:<gid> (no snapshot; production unchanged),
as a stage refused for their owner asks (a stage with staging.copy_data
gives the stores it copies to the staged users itself).""",
    "inbox": """\
Usage: boxmunge inbox [project] [--json]
       boxmunge inbox clean [project] [--yes]

List uploaded bundles, or remove them from the inbox.""",
    "secrets": """\
Usage: boxmunge secrets set (<project>|--host) KEY
       boxmunge secrets set (<project>|--host) KEY=VALUE
       boxmunge secrets get (<project>|--host) KEY
       boxmunge secrets list (<project>|--host)
       boxmunge secrets unset (<project>|--host) KEY

Manage project or host secrets. Does not support --dry-run. 'set KEY' asks
for the value without echo at a terminal, or reads it from stdin (one line),
so it is in no command line; KEY=VALUE puts it in this command's argv.""",
    "check": """\
Usage: boxmunge check <project> [--json]

Run one project's health checks (smoke tests). Read-only.""",
    "check-all": """\
Usage: boxmunge check-all [--read-only]

Check every project. Without --read-only this is the timer-driven mutator:
it writes health state, sends Pushover alerts, and stops a project's
containers on a critical result. --read-only prints the same report with no
side effects. Any other argument is an error and nothing runs. Exits with
the worst status (0 ok, 1 warning, 2 critical), and at least 1 if any
project could not be checked.""",
    "validate": """\
Usage: boxmunge validate <project> [--json]

Validate manifest, env files and compose without deploying. Read-only.""",
    "log": """\
Usage: boxmunge log [--project P] [--component C] [--level L] [--since DUR]
                    [--tail N | --all] [--containers] [--json]

Query the structured operational audit log: the last 50 matching entries
from every project, unless --project, --tail N or --all (every match) says
otherwise. DUR is e.g. 30m, 2h, 7d. --containers adds the project's
container logs and needs --project.""",
    "logs": """\
Usage: boxmunge logs <project> [service] [--staging] [--tail N] [--follow]
       boxmunge logs --host
       boxmunge logs --boxmunge

Show container logs (production's, or with --staging the staged
release's), host journal for boxmunge units, or the boxmunge service log.""",
    "backup": """\
Usage: boxmunge backup <project>

Back up, encrypt, and store locally.""",
    "backup-all": """\
Usage: boxmunge backup-all

Back up every configured project.""",
    "backup-sync": """\
Usage: boxmunge backup-sync [project]

Copy encrypted backups to the off-box remote (backup_remote in boxmunge.yml).
Never deletes anything there.""",
    "restore": """\
Usage: boxmunge restore <project> [snapshot] [--yes] [--no-safety-snapshot]

Restore from a backup snapshot (latest if none given). The snapshot is
verified before production stops, and the current data is saved as a
pre-restore safety snapshot first unless --no-safety-snapshot is given.
Does not support --dry-run.""",
    "test-restore": """\
Usage: boxmunge test-restore <project>

Verify the latest backup decrypts. Does not restore anything.""",
    "caddy-status": """\
Usage: boxmunge caddy-status

Show Caddy sites and certificate expiry.""",
    "console": """\
Usage: boxmunge console

Open the boxmunge terminal UI.""",
    "security": """\
Usage: boxmunge security [--json]
       boxmunge security <project> [--json]
       boxmunge security scan [project]
       boxmunge security scan --apply-held
       boxmunge security suppress <CVE>|--current (--project <name>|--host)
                                  --until <YYYY-MM-DD> --reason <text>
       boxmunge security unsuppress <CVE> (--project <name>|--host)
       boxmunge security resume <project> [--accept-stale-kev]

Container security and CVE policy: fleet or per-project view, scan,
suppressions, and lifting a quarantine. --until is at most 90 days ahead.
--accept-stale-kev lifts a quarantine although there is no usable CISA KEV
catalog; it is logged and alerted. It never overrides a stale catalog that
lists a CVE still in the images: deploy a release without it instead.
Operator only (refused by the deploy shell): --host suppressions, and
scan --apply-held, which applies quarantines the CVE circuit breaker held.""",
    "bundle": """\
Usage: boxmunge bundle <project-dir> [--output PATH] [--validate]

Build a validated project bundle (normally run by the client).""",
    "upgrade": """\
Usage: boxmunge upgrade [--dry-run | --apply] [--skip-self-test]
       boxmunge upgrade --target VERSION   (deploy shell only)
       boxmunge upgrade --repair-deps      (deploy shell only)

Upgrade the boxmunge platform. From the deploy shell, plain `upgrade`,
`upgrade --target` and `upgrade --repair-deps` go through the root upgrade
shim; there only those and --dry-run are accepted. --target refuses a version
older than the installed one. --repair-deps installs the installed release's
hash-pinned dependencies (MCP among them) into the live environment from its
signed bundle; it works during probation. As root, run the shim itself:
boxmunge-upgrade target VERSION, or boxmunge-upgrade repair-deps.
  --dry-run         Check migrations and config regeneration; change nothing
  --apply           Migrate/regenerate/restart only (called by the shim)
  --skip-self-test  Skip the post-upgrade self-test""",
    "userns": """\
Usage: boxmunge userns {check|migrate|rollback|commit}
       (on the server: boxmunge-server userns ..., as the shim runs it)

Root only, through the upgrade shim: sudo /opt/boxmunge/bin/boxmunge-upgrade
userns-migrate [--check] | userns-rollback | userns-commit. See OPERATIONS.md,
"User-namespace remapping".""",
    "auto-update": """\
Usage: boxmunge auto-update

Run the auto-update probation/promotion cycle.""",
    "container-update": """\
Usage: boxmunge container-update [target] [--force] [--dry-run]

Pull and recreate Caddy and project image: containers. A service that also
declares build: is not pulled: its image: names the local build. --dry-run
pulls and reports what would change without recreating anything.
Operator-only: run it as root, as boxmunge-server (its daily timer does).""",
    "_discover-update": """\
Usage: boxmunge _discover-update --json [--auto]

Internal: report an available release as JSON (used by the upgrade shim).
Without --auto, the newest release of any class. With --auto, what
auto-update would apply under this box's auto_update policy.""",
    "mcp-serve": """\
Usage: boxmunge mcp-serve

Run the MCP server on stdio for AI agent integration.""",
    "stash": """\
Usage: boxmunge stash create
       boxmunge stash restore --latest
       boxmunge stash list

Internal: platform state stashes used by the upgrade shim.""",
}


def usage_for(command: str) -> str:
    """Return the usage text for a registered command.

    Raises KeyError for an unknown command: a handler asking for usage it
    does not have is a programming error, not something to paper over.
    """
    return USAGE[command]
