"""boxmunge secrets — set, get, list, unset secrets for projects and host."""

import sys
from pathlib import Path

from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.secrets import get_key, list_keys, set_key, unset_key


def _resolve_secrets_path(
    args: list[str], paths: BoxPaths,
) -> tuple[Path | None, list[str], str | None]:
    """Return (secrets_path, remaining_args, project) from args.

    `project` is the project name for log emission, or None for --host scope.
    For project secrets: creates the project directory if it doesn't exist.
    This allows setting secrets before first deploy (pre-registration).
    """
    if args and args[0] == "--host":
        return paths.host_secrets, args[1:], None
    if args:
        project_name = args[0]
        from boxmunge.paths import validate_project_name
        try:
            validate_project_name(project_name)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return None, args[1:], None
        project_dir = paths.project_dir(project_name)
        if not project_dir.exists():
            project_dir.mkdir(parents=True)
        return paths.project_secrets(project_name), args[1:], project_name
    return None, args, None


def _cmd_set(args: list[str], paths: BoxPaths) -> int:
    secrets_path, rest, project = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY=VALUE argument", file=sys.stderr)
        return 1
    assignment = rest[0]
    if "=" not in assignment:
        print(f"ERROR: Expected KEY=VALUE, got: {assignment!r}", file=sys.stderr)
        return 1
    key, _, value = assignment.partition("=")
    try:
        set_key(secrets_path, key, value)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    log_operation("secrets", f"set {key}", paths, project=project)
    return 0


def _cmd_get(args: list[str], paths: BoxPaths) -> int:
    secrets_path, rest, _ = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY argument", file=sys.stderr)
        return 1
    key = rest[0]
    value = get_key(secrets_path, key)
    if value is None:
        print(f"ERROR: Key '{key}' not found", file=sys.stderr)
        return 1
    print(value)
    return 0


def _cmd_list(args: list[str], paths: BoxPaths) -> int:
    secrets_path, _, _ = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    for key in list_keys(secrets_path):
        print(key)
    return 0


def _cmd_unset(args: list[str], paths: BoxPaths) -> int:
    secrets_path, rest, project = _resolve_secrets_path(args, paths)
    if secrets_path is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY argument", file=sys.stderr)
        return 1
    key = rest[0]
    unset_key(secrets_path, key)
    log_operation("secrets", f"unset {key}", paths, project=project)
    return 0


_SUBCOMMANDS = {
    "set": _cmd_set,
    "get": _cmd_get,
    "list": _cmd_list,
    "unset": _cmd_unset,
}

# Arguments each subcommand takes after the subcommand name: the scope
# (<project> or --host), then KEY=VALUE or KEY where applicable.
_ARITY = {"set": 2, "get": 2, "list": 1, "unset": 2}


def secrets_usage_problem(args: list[str]) -> str | None:
    """Return why ``args`` is not a valid secrets invocation, or None.

    Every token is accounted for: an unknown subcommand, a missing or
    surplus argument, or any flag other than a leading ``--host`` scope is
    a usage error. Unknown flags such as --dry-run must never be ignored
    while the secret is written anyway (audit D-03).
    """
    if not args:
        return "missing subcommand (set, get, list, unset)"
    subcommand, rest = args[0], args[1:]
    if subcommand not in _ARITY:
        return f"Unknown subcommand '{subcommand}'"
    for i, token in enumerate(rest):
        if token == "--dry-run":
            return "'secrets' does not support --dry-run; nothing was done"
        if token.startswith("-") and not (i == 0 and token == "--host"):
            return f"unknown argument: {token}"
    if len(rest) != _ARITY[subcommand]:
        return f"'secrets {subcommand}' takes {_ARITY[subcommand]} argument(s), got {len(rest)}"
    return None


def run_secrets(args: list[str], paths: BoxPaths) -> int:
    """Dispatch secrets subcommands.

    Returns 0 on success, 2 on usage errors, 1 on operational failures
    (missing key, etc.).
    """
    from boxmunge.commands.argv import print_usage_error
    problem = secrets_usage_problem(args)
    if problem is not None:
        print_usage_error("secrets", problem)
        return 2
    return _SUBCOMMANDS[args[0]](args[1:], paths)


def cmd_secrets(args: list[str]) -> None:
    """CLI entry point for secrets command."""
    from boxmunge.commands.argv import usage_error
    problem = secrets_usage_problem(args)
    if problem is not None:
        usage_error("secrets", problem)
    paths = BoxPaths()
    sys.exit(run_secrets(args, paths))
