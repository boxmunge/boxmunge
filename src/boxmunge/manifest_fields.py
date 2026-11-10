# SPDX-License-Identifier: Apache-2.0
"""Syntax rules for the manifest fields that are written into configs or run.

Hosts, route paths and ports end up in the Caddyfile, and service names in
compose, so each is checked strictly; deploy.pre_deploy is run as a command.
Used by manifest.validate_manifest.
"""

import re
import shlex

SERVICE_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')

# Hostnames flow into the Caddyfile via simple ``", ".join(hosts)``. Any
# whitespace or Caddy directive metacharacter inside a host string would
# allow injection of arbitrary directives. The regex enforces a strict
# DNS-style label format (lowercase, hyphens between alphanumerics, TLD
# of two or more letters), with `localhost` and `*.<domain>` allowed
# explicitly. Wildcards additionally require ``allow_wildcard_hosts: true``
# at the manifest top level (TLS wildcards need DNS-01 challenge wiring).
_HOST_FORBIDDEN_CHARS = frozenset(';{}:()[]\'"`\\<>')
_HOST_LABEL_RE = re.compile(
    r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
)
_HOST_WILDCARD_RE = re.compile(
    r'^\*\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
)


def host_problem(entry: object) -> str | None:
    """Return None if the host entry is acceptable, otherwise an error string.

    Returns an error suffix to be combined with the entry name; the caller
    composes the full error message including the offending value.
    """
    if not isinstance(entry, str):
        return f"must be a string, got {type(entry).__name__}"
    if any(ch.isspace() for ch in entry):
        return "contains whitespace"
    for bad in _HOST_FORBIDDEN_CHARS:
        if bad in entry:
            return f"contains forbidden character {bad!r}"
    if entry != entry.lower():
        return "must be lowercase (DNS is case-insensitive but the manifest format is not)"
    if entry == "localhost":
        return None
    if entry.startswith("*."):
        if _HOST_WILDCARD_RE.match(entry):
            return "wildcard"  # sentinel — caller handles opt-in check
        return "is not a valid wildcard hostname"
    if _HOST_LABEL_RE.match(entry):
        return None
    return "is not a valid hostname"


# Route paths and service ports are written into the Caddyfile. Anything
# beyond a plain path (braces, whitespace, quotes, newlines) could inject
# Caddy directives, so paths are limited to unreserved URL characters and
# `/`, with an optional trailing `*` wildcard.
_ROUTE_PATH_RE = re.compile(r'^/[A-Za-z0-9._~/-]*\*?$')
_MAX_PORT = 65535


def route_path_problem(path: object) -> str | None:
    """Return why a route path is unacceptable, or None if it is fine."""
    if not isinstance(path, str):
        return f"must be a string, got {type(path).__name__}"
    if not _ROUTE_PATH_RE.fullmatch(path):
        return (
            "must start with '/' and contain only letters, digits, '.', '_', "
            "'~', '-' and '/', with an optional trailing '*' (e.g. /api/*)"
        )
    return None


def port_problem(port: object) -> str | None:
    """Return why a service port is unacceptable, or None if it is fine."""
    if isinstance(port, bool) or not isinstance(port, int):
        return (
            f"must be an unquoted integer from 1 to {_MAX_PORT} "
            f"(e.g. port: 8080), got {port!r}"
        )
    if not 1 <= port <= _MAX_PORT:
        return f"must be from 1 to {_MAX_PORT}, got {port}"
    return None


def deploy_problems(deploy: object) -> list[str]:
    """Why the manifest's deploy: block cannot be used, if it cannot.

    pre_deploy is split into words with shlex and run without a shell
    (commands.deploy.run_pre_deploy_hook), so it must be a string shlex can
    split. Absent, empty or null means no hook.
    """
    if not isinstance(deploy, dict):
        return [f"'deploy' must be a mapping, got {type(deploy).__name__}"]
    hook = deploy.get("pre_deploy")
    if hook is None or hook == "":
        return []
    if not isinstance(hook, str):
        return [f"deploy.pre_deploy must be a string (a command and its arguments, "
                f"e.g. \"boxmunge-scripts/pre-deploy.sh\"), got {type(hook).__name__}"]
    try:
        shlex.split(hook)
    except ValueError as e:
        return [f"deploy.pre_deploy {hook!r} cannot be split into words ({e}). "
                "Check its quoting; it runs without a shell, so put anything with "
                "&&, pipes or redirects in a script and name the script here."]
    return []


# container_updates.strategy: what a failed update does. The update flow
# (container_update) acts on exactly these; any other value would run as
# leave_broken, so a typo would silently pick the weaker behaviour.
VALID_STRATEGIES = ("leave_broken", "rollback_to_previous")


def strategy_problem(value: object) -> str | None:
    if value in VALID_STRATEGIES:
        return None
    return (f"container_updates.strategy {value!r} is not recognised. "
            f"Use one of: {', '.join(VALID_STRATEGIES)}.")


def retention_problem(value: object) -> str | None:
    """Why backup.retention cannot be used, if it cannot. One checker for the
    deploy-time validation and the backup run, so they cannot disagree."""
    if type(value) is int and value >= 1:
        return None
    return (f"backup.retention must be a whole number of at least 1, got "
            f"{value!r}. Set the number of backups to keep, e.g. retention: 7.")


def backup_type_problem(value: object) -> str | None:
    """backup.type is a label: the code tells only `none` from everything
    else (everything else runs dump_command and restore_command), so the one
    thing it can be wrong about is not being a string. YAML turns an unquoted
    `none`-like word such as `no` or `off` into a boolean, and an empty value
    into null, which would silently count as a backup type."""
    if isinstance(value, str) and value:
        return None
    return (f"backup.type must be a non-empty string such as 'none' or "
            f"'db-dump', got {value!r}. Quote it if it is a YAML keyword "
            f"(\"none\", not none/no/off).")
