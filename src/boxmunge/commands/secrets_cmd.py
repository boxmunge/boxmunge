"""boxmunge secrets — set, get, list, unset secrets for projects and host."""

import sys

from boxmunge.log import log_operation
from boxmunge.paths import BoxPaths
from boxmunge.secrets import (
    INTERNAL_KEYS, Inventory, LegacySecretError, QuoteSpanError, SecretsFile,
    get_internal_key, get_key, inventory, set_key, unset_key, valid_key,
)


def _resolve_secrets(
    args: list[str], paths: BoxPaths,
) -> tuple[SecretsFile | None, list[str], str | None]:
    """Return (secrets_file, remaining_args, project) from args.

    `project` is the project name for log emission, or None for --host scope.
    For project secrets: creates the project directory if it doesn't exist.
    This allows setting secrets before first deploy (pre-registration).
    """
    if args and args[0] == "--host":
        return SecretsFile.host(paths), args[1:], None
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
        return SecretsFile.project(paths, project_name), args[1:], project_name
    return None, args, None


def _scope(project: str | None) -> str:
    return project if project is not None else "--host"


def _warn_unvouched(inv: Inventory, project: str | None) -> None:
    """Say which stored keys containers may not receive as boxmunge reports."""
    scope = _scope(project)
    own = [k for k in inv.legacy if k in INTERNAL_KEYS]
    app = [k for k in inv.legacy if k not in INTERNAL_KEYS]
    if own:
        print(
            f"NOTE: {', '.join(own)} in {scope} secrets predate literal storage; "
            "stage reads them as before. 'secrets set' them again to store them "
            "literally.", file=sys.stderr,
        )
    if app:
        print(
            f"WARNING: {', '.join(app)} in {scope} secrets predate literal "
            "storage: Compose interprets $, ' #', quotes and surrounding spaces "
            "in them, so containers may not receive the value as set. Check "
            f"each with 'secrets get {scope} KEY' and set it again.",
            file=sys.stderr,
        )
    if inv.misnamed:
        print(
            f"WARNING: {', '.join(repr(k) for k in inv.misnamed)} in {scope} "
            "secrets are not valid key names (letters, digits and underscores, "
            "not starting with a digit); Compose still passes them to "
            f"containers. Set each under a valid name, update the app, then "
            f"'secrets unset {scope} <old name>'.", file=sys.stderr,
        )


def _report_quote_span(e: QuoteSpanError, project: str | None) -> None:
    scope = _scope(project)
    print(
        f"ERROR: {', '.join(e.keys)} in {scope} secrets were stored by an older "
        "boxmunge with a quote their line does not close, so Compose can read "
        "the lines after them into those values; until they are cleared, any "
        "other change could alter what containers receive. Clear each one, "
        "either removing it or setting it again, then retry:", file=sys.stderr,
    )
    for k in e.keys:
        print(f"  secrets unset {scope} {k}    or    secrets set {scope} '{k}=<value>'",
              file=sys.stderr)


def _record_write(op: str, key: str, inv: Inventory, paths: BoxPaths,
                  project: str | None) -> None:
    msg = f"{op} {key}"
    if inv.migrated:
        # Lossless: these keys' old unquoted lines already read literally.
        msg += f"; re-encoded as literal values: {', '.join(inv.migrated)}"
    kept = inv.legacy + inv.misnamed
    if kept:
        msg += f"; old lines kept as stored: {', '.join(kept)}"
    log_operation("secrets", msg, paths, project=project)
    _warn_unvouched(inv, project)


def _cmd_set(args: list[str], paths: BoxPaths) -> int:
    secrets, rest, project = _resolve_secrets(args, paths)
    if secrets is None:
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
        inv = set_key(secrets, key, value)
    except QuoteSpanError as e:
        _report_quote_span(e, project)
        return 1
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    _record_write("set", key, inv, paths, project)
    return 0


def _cmd_get(args: list[str], paths: BoxPaths) -> int:
    secrets, rest, project = _resolve_secrets(args, paths)
    if secrets is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY argument", file=sys.stderr)
        return 1
    key = rest[0]
    try:
        # boxmunge's own keys print what stage uses, old format or not.
        value = get_internal_key(secrets, key) if key in INTERNAL_KEYS else get_key(secrets, key)
    except LegacySecretError as e:
        if not valid_key(key):
            print(
                f"ERROR: {key!r} is not a valid key name, stored by an older "
                f"boxmunge as {e.stored!r} (Compose's reading of it may differ). "
                f"Set it under a valid name, then 'secrets unset {_scope(project)} "
                f"{key}'.", file=sys.stderr,
            )
            return 1
        print(
            f"ERROR: {key} predates literal storage and is stored unquoted as "
            f"{e.stored!r}. Compose interprets $, ' #', quotes and surrounding "
            "spaces in that text, so containers may not receive it as written. "
            f"Set it again to store it literally: secrets set {_scope(project)} "
            f"'{key}=<value>'", file=sys.stderr,
        )
        return 1
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if value is None:
        print(f"ERROR: Key '{key}' not found", file=sys.stderr)
        return 1
    print(value)
    return 0


def _cmd_list(args: list[str], paths: BoxPaths) -> int:
    secrets, _, project = _resolve_secrets(args, paths)
    if secrets is None:
        return 1
    try:
        inv = inventory(secrets)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    for key in inv.keys:
        print(key)
    _warn_unvouched(inv, project)
    return 0


def _cmd_unset(args: list[str], paths: BoxPaths) -> int:
    secrets, rest, project = _resolve_secrets(args, paths)
    if secrets is None:
        return 1
    if not rest:
        print("ERROR: Missing KEY argument", file=sys.stderr)
        return 1
    key = rest[0]
    try:
        inv = unset_key(secrets, key)
    except QuoteSpanError as e:
        _report_quote_span(e, project)
        return 1
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    _record_write("unset", key, inv, paths, project)
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
