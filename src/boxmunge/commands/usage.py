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
security, cve, cve-incident, writable.""",
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
Usage: boxmunge stage <project> [--ref REF] [--dry-run]

Deploy alongside production on the staging hostname for verification.""",
    "promote": """\
Usage: boxmunge promote <project> [--dry-run]

Promote the staged build to production.""",
    "unstage": """\
Usage: boxmunge unstage <project> [--dry-run]

Tear down staging.""",
    "prod-deploy": """\
Usage: boxmunge prod-deploy <project> [--ref REF] [--no-snapshot] [--dry-run]
       boxmunge prod-deploy <project> --abandon

Deploy directly to production (skips staging). --abandon undoes an install
that stopped before its pre-deploy hook ran: the replaced release's files
go back; containers and data are not touched.""",
    "rollback": """\
Usage: boxmunge rollback <project> [--yes]

Restore the previous deployment. Does not support --dry-run.""",
    "pause": """\
Usage: boxmunge pause <project> [--reason TEXT] [--yes]

Take a project offline behind a styled maintenance page. Does not support
--dry-run.""",
    "resume": """\
Usage: boxmunge resume <project> [--skip-security-checks] [--yes]

Bring a paused project back online (pulls latest images first). Does not
support --dry-run.""",
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
    "project-delete": """\
Usage: boxmunge project-delete <project> [--yes] [--force]

Destructive: stop the project, remove its files, and deregister it. Asks for
confirmation unless --yes. If container teardown fails, nothing is deleted
and the command exits 1; --force deletes anyway. Does not support --dry-run.""",
    "inbox": """\
Usage: boxmunge inbox [project] [--json]
       boxmunge inbox clean [project] [--yes]

List uploaded bundles, or remove them from the inbox.""",
    "secrets": """\
Usage: boxmunge secrets set (<project>|--host) KEY=VALUE
       boxmunge secrets get (<project>|--host) KEY
       boxmunge secrets list (<project>|--host)
       boxmunge secrets unset (<project>|--host) KEY

Manage project or host secrets. Does not support --dry-run.""",
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

Query the structured operational audit log. DUR is e.g. 30m, 2h, 7d.""",
    "logs": """\
Usage: boxmunge logs <project> [service] [--tail N] [--follow]
       boxmunge logs --host
       boxmunge logs --boxmunge

Show container logs, host journal for boxmunge units, or the boxmunge
service log.""",
    "backup": """\
Usage: boxmunge backup <project>

Back up, encrypt, and store locally.""",
    "backup-all": """\
Usage: boxmunge backup-all

Back up every configured project.""",
    "backup-sync": """\
Usage: boxmunge backup-sync [project]

Sync encrypted backups to the off-box remote.""",
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
       boxmunge security resume <project>

Container security and CVE policy: fleet or per-project view, scan,
suppressions, and lifting a quarantine. --until is at most 90 days ahead.
Operator only (refused by the deploy shell): --host suppressions, and
scan --apply-held, which applies quarantines the CVE circuit breaker held.""",
    "bundle": """\
Usage: boxmunge bundle <project-dir> [--output PATH] [--validate]

Build a validated project bundle (normally run by the client).""",
    "upgrade": """\
Usage: boxmunge upgrade [--dry-run | --apply] [--skip-self-test]
       boxmunge upgrade --target VERSION   (deploy shell only)

Upgrade the boxmunge platform. From the deploy shell, plain `upgrade` and
`upgrade --target` go through the root upgrade shim.
  --dry-run         Check migrations and config regeneration; change nothing
  --apply           Migrate/regenerate/restart only (called by the shim)
  --skip-self-test  Skip the post-upgrade self-test""",
    "auto-update": """\
Usage: boxmunge auto-update

Run the auto-update probation/promotion cycle.""",
    "container-update": """\
Usage: boxmunge container-update [target] [--force] [--dry-run]

Pull and recreate Caddy and project image: containers. A service that also
declares build: is not pulled: its image: names the local build. --dry-run
pulls and reports what would change without recreating anything.""",
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
