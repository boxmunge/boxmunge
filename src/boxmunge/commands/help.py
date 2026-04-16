"""Help and agent-help commands."""

import sys

HELP_TEXT = """\
boxmunge — minimalist, agent-friendly VPS hosting framework

Usage: boxmunge <command> [options]

Host operations:
  help [command]          Show help (this text, or detailed help for a command)
  agent-help              AI agent orientation
  doctor                  Verify host health and configuration
  status                  Dashboard of all projects and host state
  test-alert              Send a test Pushover notification

Project lifecycle:
  add-git-project <name> <repo>  Create a project from a git repo
  stage <project>         Stage from latest source alongside production
  promote <project>       Promote staging to production
  unstage <project>       Tear down staging
  deploy <project>        Deploy directly to production
  rollback <project>      Restore previous deployment
  remove-project <p>      Deregister and clean up (with confirmation)
  diff <project>          Preview what a deploy would change

Inbox:
  inbox [project]         List uploaded bundles
  inbox clean [project]   Remove old bundles from inbox

Secrets:
  secrets set <project> KEY=VALUE   Set a project secret
  secrets set --host KEY=VALUE      Set a host-level secret
  secrets list <project|--host>     List secret keys
  secrets get <project|--host> KEY  Read a secret value
  secrets unset <project|--host> K  Remove a secret

Project operations:
  check <project>         Run health checks (docker + http + smoke)
  check-all               Check all projects
  logs <project>          View container logs
  backup <project>        Backup, encrypt, store locally
  backup-all              Backup all configured projects
  backup-sync [proj]      Sync encrypted backups to off-box remote
  restore <project>       Restore from a backup snapshot
  list-projects           List registered projects with brief status
  validate <project>      Validate manifest, env, compose without deploying
  caddy-status            Show Caddy sites and certificate expiry
  test-restore <proj>     Verify backup restores into throwaway container

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
  Or skip staging:  deploy <project>

Deploying a git-based project:
  1. First time:  add-git-project <name> <repo-url>
  2. Stage:  stage <project> --ref <branch-or-tag>
  3. Verify, then:  promote <project>
  Or skip staging:  deploy <project> --ref <tag>

Managing secrets:
  secrets set <project> DB_URL="postgres://..."
  secrets set --host GITHUB_TOKEN=ghp_xxx
  secrets list <project>

First moves:
  status              — see what's running
  list-projects       — see what's deployed
  doctor              — check host health
  inbox               — see uploaded bundles

When in doubt, use --dry-run first.

For detailed documentation, run:
  agent-help architecture     How the system is structured
  agent-help operations       Step-by-step operational guides
  agent-help conventions      Project manifest and conventions
  agent-help rules            Agent guardrails and safe practices
"""

# Map topic names to on-server doc filenames
AGENT_HELP_TOPICS: dict[str, str] = {
    "architecture": "ARCHITECTURE.md",
    "operations": "OPERATIONS.md",
    "conventions": "PROJECT_CONVENTIONS.md",
    "rules": "AGENT_RULES.md",
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
