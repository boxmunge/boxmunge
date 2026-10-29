"""Help and agent-help commands."""

import sys

from boxmunge.commands.usage import USAGE

HELP_TEXT = """\
boxmunge — minimalist, agent-friendly VPS hosting framework

Usage: boxmunge <command> [options]

Host operations:
  help [command]          Show help (this text, or detailed help for a command)
  agent-help              AI agent orientation
  version                 Show installed boxmunge version
  doctor                  Verify host health and configuration
  status                  Dashboard of all projects (status, last check, deployed-at)
  health                  Run platform-wide health checks
  self-test               Run canary self-test to verify platform integrity
  handshake               Print server version and compatibility info
  test-alert              Send a test Pushover notification

Project lifecycle:
  add-git-project <name> <repo>  Register a git-backed project
  stage <project>         Stage alongside production for verification
  promote <project>       Promote staging to production
  unstage <project>       Tear down staging
  prod-deploy <project>   Deploy directly to production (skip staging)
  prod-deploy <p> --abandon  Put back the files of an install left open
  rollback <project>      Restore previous deployment
  pause <project>         Take offline with a styled maintenance page
  resume <project>        Bring back online (pulls latest images first)
  recover <project>       Un-stop a health-monitor-stopped prod (same build)
  diff <project>          Preview what a deploy would change
  project-add <name>      Register a project name in the allowlist
  project-list            List registered project names
  project-delete <p>      Destructive: stop, remove files, deregister (with confirm)
  data adopt <p> <svc>:<path> <name>
                          Copy an anonymous volume into a named one deploy adopts
  data chown <p> <svc> <uid>:<gid>
                          Give a service's data to its new user (stays stopped
                          until you deploy)

Inbox & secrets:
  inbox [project]         List uploaded bundles
  inbox clean [project]   Remove bundles from the inbox (asks unless --yes)
  secrets set <p> KEY=VAL Set a project secret
  secrets set --host K=V  Set a host-level secret
  secrets list <p|--host> List secret keys
  secrets get <p|--host> K  Read a secret value
  secrets unset <p|--host> K  Remove a secret

Project operations:
  check <project>         Run health checks (docker + http + smoke)
  check-all [--read-only] Check all projects (--read-only skips state writes,
                          Pushover alerts, and compose_down on critical)
  validate <project>      Validate manifest, env, compose without deploying
  log [filters]           Query structured operational audit log (deploy/check/rollback)
  logs <project> [svc]    Tail container logs (--follow, --tail N)
  logs --host             Show host journalctl for boxmunge-* units
  logs --boxmunge         Tail the boxmunge service log
  backup <project>        Backup, encrypt, store locally
  backup-all              Backup all configured projects
  backup-sync [project]   Copy encrypted backups to off-box remote (never deletes)
  restore <project>       Restore from a backup snapshot
  test-restore <project>  Verify latest backup decrypts (no restore run)
  caddy-status            Show Caddy sites and certificate expiry
  console                 Open the boxmunge TUI

Container security & CVE policy:
  security                        Fleet CVE summary (use --json for parseable)
  security <project>              Per-project view (hardening + CVE state)
  security scan [<project>]       Run Trivy scan now (no project = fleet)
  security suppress <CVE>         Add a CVE suppression with --until and --reason
  security suppress --current     Suppress all currently-quarantining CVEs
                                  for --project, or --host (across all projects)
  security suppress --host        Host-scope suppression (applies to every project on this box)
  security unsuppress <CVE>       Remove a suppression (--project NAME or --host)
  security resume <project>       Lift a CVE quarantine (re-scans first)
  security scan --apply-held      Apply quarantines the circuit breaker held (operator)

Platform updates:
  upgrade                 Upgrade boxmunge platform from latest release
  upgrade --target VER    Upgrade to a specific newer version (e.g. 0.3.5)
  auto-update             Run the auto-update probation/promotion cycle
  mcp-serve               Run MCP server (stdio) for AI agent integration

Operator only (as root, not in the deploy shell):
  container-update        Pull and recreate Caddy and project image: containers
  install-txn <p> --drop  Drop a stale install record
  project-forget <p>      Drop a registry entry whose project directory is gone
  legacy-stage <p> ...    Resolve a release staged by boxmunge 0.10.1
  boxmunge-upgrade userns-migrate [--check] | userns-rollback | userns-commit
                          Remap Docker's user namespaces (OPERATIONS.md)

Options (run 'help <command>' to see exactly which a command accepts):
  -h, --help              Show a command's usage; never runs the command
  --dry-run               Preview without changing anything. Only prod-deploy,
                          stage, promote, unstage and upgrade (and the operator's
                          container-update) support it; every other command
                          rejects it
  --yes                   Skip confirmation prompts (where the command asks)
  --json                  Machine-readable JSON output (where supported)

An unknown or unsupported flag is an error (exit 2); nothing is run.

Upload bundles with: scp -O -P 922 (or the SSH port chosen at install) bundle.tar.gz deploy@<host>:

If you are an AI agent, run: agent-help
"""

AGENT_HELP_TEXT = """\
boxmunge agent orientation
==========================

You are operating a boxmunge-managed VPS through a restricted deploy shell.
Only boxmunge commands exist here. 'help <command>' shows usage and never
runs it. This page is short on purpose: read all of it.

Rules that prevent outages (building or changing a project):
  1. Base image: the smallest official image for your stack (-slim or
     distroless), pinned by digest. Never a full or generic distro image:
     every OS package is CVE surface, and a CVE in a package your app never
     uses can still quarantine the site.          -> agent-help images
  2. Multi-stage builds: compilers, pip/npm caches and build headers stay in
     the builder stage, never in the runtime image.
  3. Root filesystems are read-only. Declare every path the app writes in
     the manifest's writable: block.              -> agent-help writable
     Services run non-root: a registry image without a non-root USER needs
     services.<svc>.security.user (image/root need a reason).
  4. All ingress goes through Caddy. Do not publish ports: in compose.
  5. smoke.sh is POSIX sh and exits 0 only when the app really works.
                                                  -> agent-help conventions
  6. Run 'validate <project>' before every deploy.
  7. Fix a CVE alert by rebuilding or slimming the image, not by
     suppressing it. Suppress only with evidence. -> agent-help cve-incident

Operating safely:
  - Check 'status' before and after changes.
  - Unknown flags are errors (exit 2) and nothing runs. --dry-run works on
    prod-deploy, stage, promote, unstage and upgrade; other commands
    refuse it.
  - QUARANTINED or STILL_RUNNING_AT_RISK in any output: stop and follow
    agent-help cve-incident.

Deploying a bundle-based project (the recommended path):
  1. Build locally:  boxmunge bundle ./myproject
  2. Upload:         scp -O -P 922 <bundle>.tar.gz deploy@<host>:
  3. Verify:         stage <project>    (check https://staging.<host>)
  4. Go live:        promote <project>
  Or skip staging:   prod-deploy <project>

Git-based projects are supported but being reworked; prefer bundles.
                                                  -> agent-help operations

Secrets:  secrets set <project> DB_URL="postgres://..."
          secrets list <project>

Maintenance:  pause <project>   (visitors see a maintenance page)
              resume <project>  (brings it back; pulls latest images first)

First moves:  status, doctor, inbox, log --tail 50

Topics (agent-help <topic>):
  images        Choosing a base image (read before writing a Dockerfile)
  conventions   Project manifest, scripts, and layout
  writable      The writable: manifest block
  rules         Agent guardrails and safe practices
  operations    Step-by-step operational guides
  security      Container security model and opt-outs
  cve           CVE policy reference
  cve-incident  Playbook for a CVE alert
  architecture  How the system is structured
"""

# Map topic names to on-server doc filenames
AGENT_HELP_TOPICS: dict[str, str] = {
    "images": "IMAGES.md",
    "architecture": "ARCHITECTURE.md",
    "operations": "OPERATIONS.md",
    "conventions": "PROJECT_CONVENTIONS.md",
    "rules": "AGENT_RULES.md",
    "security": "SECURITY.md",
    "cve": "CVE_POLICY.md",
    "cve-incident": "CVE_INCIDENT_PLAYBOOK.md",
    # writable: shares the conventions doc — schema + worked examples live there
    "writable": "PROJECT_CONVENTIONS.md",
}


def _resolve_hostname() -> str:
    """Try to read hostname from boxmunge config. Falls back to <host>."""
    try:
        from boxmunge.config import load_config
        from boxmunge.paths import BoxPaths
        config = load_config(BoxPaths())
        return config.get("hostname", "<host>")
    except Exception:
        return "<host>"


def _substitute_hostname(text: str) -> str:
    hostname = _resolve_hostname()
    return text.replace("deploy@<host>:", f"deploy@{hostname}:")


def cmd_help(args: list[str]) -> None:
    """Show the overview, or one command's usage. Never runs the command.

    Usage comes from the static table in ``commands.usage``. Calling a
    handler to make it print its usage would execute every command that
    takes no required argument (audit D-01).
    """
    if len(args) > 1:
        print(f"ERROR: unexpected argument(s): {' '.join(args[1:])}",
              file=sys.stderr)
        print(USAGE["help"], file=sys.stderr)
        sys.exit(2)
    if args:
        if args[0] not in USAGE:
            print(f"ERROR: Unknown command '{args[0]}'. "
                  "Run 'help' for the command list.", file=sys.stderr)
            sys.exit(2)
        print(USAGE[args[0]])
        sys.exit(0)
    print(_substitute_hostname(HELP_TEXT))
    sys.exit(0)


def cmd_init_host(args: list[str]) -> None:
    """init-host is the root bootstrap script, not a server command."""
    print(f"ERROR: {USAGE['init-host']}", file=sys.stderr)
    sys.exit(2)


def cmd_agent_help(args: list[str]) -> None:
    """Show agent-specific orientation, or a detailed topic."""
    if len(args) > 1:
        print(f"ERROR: unexpected argument(s): {' '.join(args[1:])}",
              file=sys.stderr)
        print(USAGE["agent-help"], file=sys.stderr)
        sys.exit(2)

    if args:
        topic = args[0].lower()
        if topic in AGENT_HELP_TOPICS:
            # Try on-server docs first, fall back to repo docs
            from boxmunge.paths import BoxPaths
            paths = BoxPaths()
            doc_file = paths.docs / AGENT_HELP_TOPICS[topic]
            if not doc_file.exists():
                print(f"ERROR: Documentation not found: {doc_file}", file=sys.stderr)
                sys.exit(1)
            print(doc_file.read_text())
            sys.exit(0)
        else:
            print(f"ERROR: Unknown topic '{topic}'. Available topics:",
                  file=sys.stderr)
            for name in sorted(AGENT_HELP_TOPICS):
                print(f"  {name}", file=sys.stderr)
            sys.exit(2)

    print(_substitute_hostname(AGENT_HELP_TEXT))
    sys.exit(0)
