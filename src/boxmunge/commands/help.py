"""Help and agent-help commands."""

import sys

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
  rollback <project>      Restore previous deployment
  pause <project>         Take offline with a styled maintenance page
  resume <project>        Bring back online (pulls latest images first)
  diff <project>          Preview what a deploy would change
  project-add <name>      Register a project name in the allowlist
  project-list            List registered project names
  project-delete <p>      Destructive: stop, remove files, deregister (with confirm)

Inbox & secrets:
  inbox [project]         List uploaded bundles
  inbox clean [project]   Remove old bundles from inbox
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
  backup-sync [project]   Sync encrypted backups to off-box remote
  restore <project>       Restore from a backup snapshot
  test-restore <project>  Verify backup restores into throwaway container
  caddy-status            Show Caddy sites and certificate expiry
  console                 Open the boxmunge TUI

Container security & CVE policy:
  security                        Fleet CVE summary (use --json for parseable)
  security <project>              Per-project view (hardening + CVE state)
  security scan [<project>]       Run Trivy scan now (no project = fleet)
  security suppress <CVE>         Add a CVE suppression with --until and --reason
  security unsuppress <CVE>       Remove a suppression
  security resume <project>       Lift a CVE quarantine (re-scans first)

Platform updates:
  upgrade                 Upgrade boxmunge platform from latest release
  upgrade --target VER    Pin platform to a specific version (e.g. 0.3.5)
  auto-update             Run the auto-update probation/promotion cycle
  container-update        Pull and recreate Caddy and project image: containers
  mcp-serve               Run MCP server (stdio) for AI agent integration

Options:
  --dry-run               Show what would happen without doing it
  --yes                   Skip confirmation prompts
  --json                  Machine-readable JSON output (where supported)

Upload bundles with: scp bundle.tar.gz deploy@<host>:

If you are an AI agent, run: agent-help
"""

AGENT_HELP_TEXT = """\
boxmunge agent orientation
==========================

You are operating a boxmunge-managed VPS through a restricted deploy shell.
Only boxmunge commands are available — there is no general shell access.

Key principles:
  - Use the commands listed in 'help'. There are no other commands.
  - Use --dry-run before destructive commands you're unsure about.
  - Use 'validate <project>' before deploying new/modified projects.
  - Check 'status' before and after making changes.

Deploying a bundle-based project:
  1. Build a tar.gz bundle locally:  boxmunge bundle ./myproject
  2. Upload:  scp -P 922 bundle.tar.gz deploy@<host>:
  3. Verify:  stage <project>    (check staging.<hostname>)
  4. Go live:  promote <project>
  Or skip staging:  prod-deploy <project>

Deploying a git-based project:
  1. First time:  add-git-project <name> <repo-url>
  2. Stage:  stage <project> --ref <branch-or-tag>
  3. Verify, then:  promote <project>
  Or skip staging:  prod-deploy <project> --ref <tag>

Managing secrets:
  secrets set <project> DB_URL="postgres://..."
  secrets set --host GITHUB_TOKEN=ghp_xxx
  secrets list <project>

Scheduled maintenance:
  pause <project>     — take offline; visitors see a maintenance page
  resume <project>    — bring back online; pulls latest images first
                        (use --skip-security-checks only in emergencies)

First moves:
  status              — see what's deployed and its health
  doctor              — check host health
  inbox               — see uploaded bundles
  log --tail 50       — recent ops audit (deploys, checks, rollbacks)

When in doubt, use --dry-run first.

For detailed documentation, run:
  agent-help architecture     How the system is structured
  agent-help operations       Step-by-step operational guides
  agent-help conventions      Project manifest and conventions
  agent-help rules            Agent guardrails and safe practices
  agent-help security         Container security model and opt-outs
  agent-help cve              CVE policy reference (posture, suppressions, scan)
  agent-help cve-incident     Step-by-step playbook for handling a CVE alert
  agent-help writable         writable: manifest block (v0.9 schema 3)
"""

# Map topic names to on-server doc filenames
AGENT_HELP_TOPICS: dict[str, str] = {
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
    """Show help text, or per-command help if a command name is given."""
    if args:
        # Delegate to the command with no args — most commands print usage
        from boxmunge.cli import COMMANDS
        handler = COMMANDS.get(args[0])
        if handler:
            handler([])
        else:
            print(f"Unknown command '{args[0]}'.", file=sys.stderr)
            sys.exit(2)
        return
    print(_substitute_hostname(HELP_TEXT))
    sys.exit(0)


def cmd_agent_help(args: list[str]) -> None:
    """Show agent-specific orientation, or a detailed topic."""
    from pathlib import Path

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
            print(f"Unknown topic '{topic}'. Available topics:", file=sys.stderr)
            for name in sorted(AGENT_HELP_TOPICS):
                print(f"  {name}", file=sys.stderr)
            sys.exit(2)

    print(_substitute_hostname(AGENT_HELP_TEXT))
    sys.exit(0)
