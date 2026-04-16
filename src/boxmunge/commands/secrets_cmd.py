"""boxmunge secrets — set, get, list, unset secrets for projects and host."""

import sys
from pathlib import Path

from boxmunge.paths import BoxPaths
from boxmunge.secrets import get_key, list_keys, read_dotenv, set_key, unset_key


def _resolve_secrets_path(args: list[str], paths: BoxPaths) -> tuple[Path | None, list[str]]:
    """Return (secrets_path, remaining_args) from a --host or project-name args list.

    For project secrets: creates the project directory if it doesn't exist.
    This allows setting secrets before first deploy (pre-registration).
    """
    if args and args[0] == "--host":
        return paths.host_secrets, args[1:]
    if args:
        project_name = args[0]
        from boxmunge.paths import validate_project_name
        try:
            validate_project_name(project_name)
        except ValueError as e:
            print(f"ERROR: {e}")
            return None, args[1:]
        project_dir = paths.project_dir(project_name)
        if not project_dir.exists():
            project_dir.mkdir(parents=True)
        return paths.project_secrets(project_name), args[1:]
    return None, args


def _cmd_set(args: list[str], paths: BoxPaths) -> int:
    secrets_path, rest = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY=VALUE argument")
        return 1
    assignment = rest[0]
    if "=" not in assignment:
        print(f"ERROR: Expected KEY=VALUE, got: {assignment!r}")
        return 1
    key, _, value = assignment.partition("=")
    set_key(secrets_path, key, value)
    return 0


def _cmd_get(args: list[str], paths: BoxPaths) -> int:
    secrets_path, rest = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY argument")
        return 1
    key = rest[0]
    value = get_key(secrets_path, key)
    if value is None:
        print(f"ERROR: Key '{key}' not found")
        return 1
    print(value)
    return 0


def _cmd_list(args: list[str], paths: BoxPaths) -> int:
    secrets_path, _ = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    for key in list_keys(secrets_path):
        print(key)
    return 0


def _cmd_unset(args: list[str], paths: BoxPaths) -> int:
    secrets_path, rest = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY argument")
        return 1
    unset_key(secrets_path, rest[0])
    return 0


_SUBCOMMANDS = {
    "set": _cmd_set,
    "get": _cmd_get,
    "list": _cmd_list,
    "unset": _cmd_unset,
}


def run_secrets(args: list[str], paths: BoxPaths) -> int:
    """Dispatch secrets subcommands. Returns 0 on success, 1 on failure."""
    if not args:
        print("Usage: boxmunge secrets <set|get|list|unset> [--host | <project>] ...")
        return 1
    subcommand = args[0]
    handler = _SUBCOMMANDS.get(subcommand)
    if handler is None:
        print(f"ERROR: Unknown subcommand '{subcommand}'")
        return 1
    return handler(args[1:], paths)


def cmd_secrets(args: list[str]) -> None:
    """CLI entry point for secrets command."""
    paths = BoxPaths()
    sys.exit(run_secrets(args, paths))
