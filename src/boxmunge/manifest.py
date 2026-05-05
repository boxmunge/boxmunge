# SPDX-License-Identifier: Apache-2.0
"""Load and validate project manifests (manifest.yml)."""

import re
from pathlib import Path
from typing import Any

import yaml

_VALID_SERVICE_NAME = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')

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


def _validate_host(entry: object) -> str | None:
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


CURRENT_SCHEMA_VERSION = 2


class ManifestError(Exception):
    """Raised when a manifest file cannot be loaded."""


def load_manifest(path: Path) -> dict[str, Any]:
    """Load a manifest.yml file and return its contents as a dict.

    Raises ManifestError if the file doesn't exist or can't be parsed.
    """
    if not path.exists():
        raise ManifestError(f"Manifest not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ManifestError(f"Manifest is not a YAML mapping: {path}")

    return data


def validate_manifest(
    manifest: Any, expected_name: str
) -> tuple[list[str], list[str]]:
    """Validate a parsed manifest against the boxmunge project conventions.

    Returns (errors, warnings). errors is empty if the manifest is valid.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Top-level shape guard. A YAML document like a list (`- foo`), scalar
    # (`just a string`), or empty file (`None`) would otherwise AttributeError
    # deep inside the validator on the first .get() call. Surface a single
    # clear error and stop.
    if not isinstance(manifest, dict):
        errors.append("manifest.yml must be a YAML mapping at the top level")
        return errors, warnings

    # Schema version check
    schema_version = manifest.get("schema_version", 1)
    if not isinstance(schema_version, int) or schema_version < 1 or schema_version > CURRENT_SCHEMA_VERSION:
        errors.append(
            f"Unsupported schema_version {schema_version!r}. "
            f"This boxmunge supports schema_version up to {CURRENT_SCHEMA_VERSION}. "
            f"Upgrade boxmunge to use this manifest."
        )
        return errors, warnings  # Can't validate further

    # Project name
    project = manifest.get("project", "")
    if not project:
        errors.append("Required field 'project' is missing.")
    elif project != expected_name:
        errors.append(
            f"Project name '{project}' does not match directory name "
            f"'{expected_name}'."
        )

    # Hosts
    hosts = manifest.get("hosts", [])
    if not hosts:
        errors.append("'hosts' must contain at least one hostname.")
    elif not isinstance(hosts, list):
        errors.append("'hosts' must be a list")
    else:
        allow_wildcard = bool(manifest.get("allow_wildcard_hosts", False))
        for entry in hosts:
            problem = _validate_host(entry)
            if problem is None:
                continue
            if problem == "wildcard":
                if allow_wildcard:
                    continue
                errors.append(
                    f"wildcard host {entry!r} requires 'allow_wildcard_hosts: "
                    f"true' at the manifest top level"
                )
                continue
            errors.append(f"host {entry!r} is invalid: {problem}")

    # Services
    services = manifest.get("services", {})
    if not isinstance(services, dict):
        errors.append("'services' must be a mapping")
        return errors, warnings  # Can't validate further with a malformed services block
    if not services:
        errors.append("'services' must define at least one service.")
    else:
        for svc_name, svc in services.items():
            if not _VALID_SERVICE_NAME.match(svc_name):
                errors.append(f"Service name '{svc_name}' is invalid. Must be lowercase alphanumeric with hyphens.")
            if "port" not in svc:
                errors.append(f"Service '{svc_name}' is missing 'port'.")
            routes = svc.get("routes", [])
            if not routes:
                errors.append(
                    f"Service '{svc_name}' must have at least one route."
                )
            else:
                for i, route in enumerate(routes):
                    if not isinstance(route, dict) or "path" not in route:
                        errors.append(
                            f"Service '{svc_name}' route {i}: must be "
                            f"a mapping with 'path' key, e.g. {{path: /}}, "
                            f"got: {route!r}"
                        )

            if "limits" not in svc:
                warnings.append(
                    f"Service '{svc_name}' has no resource limits. "
                    "Consider setting memory/cpu limits to prevent resource starvation."
                )

    # Security block — optional. Validates project-level and per-service blocks.
    from boxmunge.security_overlay import (
        SecurityValidationError,
        validate_security_block,
    )

    project_security = manifest.get("security")
    if project_security is not None and not isinstance(project_security, dict):
        errors.append("'security' must be a mapping")
        # Skip remaining security validation rather than feed garbage downstream.
        project_security = None
    has_any_security_block = project_security is not None or any(
        isinstance(svc, dict) and svc.get("security") is not None
        for svc in services.values()
    )
    if has_any_security_block and schema_version < 2:
        errors.append(
            f"manifest declares a 'security:' block but schema_version is "
            f"{schema_version}. The 'security:' block requires schema_version: 2 "
            f"(boxmunge 0.5.0+). Bump schema_version to 2 — boxmunge upgrades "
            f"existing v1 manifests automatically; the migration is a no-op."
        )

    try:
        validate_security_block(project_security, context="project")
    except SecurityValidationError as e:
        errors.append(str(e))

    for svc_name, svc in services.items():
        svc_security = svc.get("security") if isinstance(svc, dict) else None
        try:
            validate_security_block(svc_security, context=f"service:{svc_name}")
        except SecurityValidationError as e:
            errors.append(str(e))

    # Backup
    backup = manifest.get("backup", {})
    if not isinstance(backup, dict):
        errors.append("'backup' must be a mapping")
        backup = {}
    backup_type = backup.get("type", "none")
    if backup_type != "none":
        if not backup.get("dump_command"):
            errors.append(
                f"Backup type is '{backup_type}' but 'dump_command' is missing. "
                "No write-only backups — both dump and restore are required."
            )
        if not backup.get("restore_command"):
            errors.append(
                f"Backup type is '{backup_type}' but 'restore_command' is missing. "
                "No write-only backups — both dump and restore are required."
            )

    # Smoke tests — per-service
    has_any_smoke = any(
        svc.get("smoke") for svc in services.values()
    ) if services else False
    if not has_any_smoke:
        warnings.append(
            "No smoke tests configured. Strongly recommended to set "
            "'smoke' on at least one service."
        )

    # Project ID (ULID) — mandatory
    project_id = manifest.get("id", "")
    if not project_id:
        errors.append(
            "Required field 'id' is missing. "
            "Use 'boxmunge bundle' to generate a ULID automatically."
        )

    # Source type — mandatory
    source = manifest.get("source", "")
    if not source:
        errors.append(
            "Required field 'source' is missing. "
            "Specify 'source: bundle' or 'source: git'."
        )
    elif source not in ("bundle", "git"):
        errors.append(
            f"'source' must be 'bundle' or 'git', got '{source}'."
        )
    elif source == "git":
        if not manifest.get("repo"):
            errors.append(
                "'source' is 'git' but 'repo' is missing. "
                "Specify the git repository URL."
            )

    # Staging (optional)
    staging = manifest.get("staging", {})
    if staging and not isinstance(staging, dict):
        errors.append("'staging' must be a mapping")
        staging = {}
    if staging:
        _STAGING_KEYS = {"copy_data"}
        unknown_staging = set(staging.keys()) - _STAGING_KEYS
        for key in sorted(unknown_staging):
            warnings.append(f"Unknown key in 'staging': '{key}'")
        copy_data = staging.get("copy_data")
        if copy_data is not None and not isinstance(copy_data, bool):
            errors.append(
                f"'staging.copy_data' must be a boolean, got {type(copy_data).__name__}."
            )

    return errors, warnings


def get_routable_services(
    manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return services that should be connected to the boxmunge-proxy network.

    Excludes services marked internal: true.
    """
    result = {}
    for name, svc in manifest.get("services", {}).items():
        if not svc.get("internal", False):
            result[name] = svc
    return result


def get_all_routes(
    manifest: dict[str, Any],
) -> list[tuple[str, str, int]]:
    """Return all routes as (path, service_alias, port) sorted by specificity.

    More specific paths (longer, more segments) come first so Caddy's
    first-match routing works correctly.
    """
    project = manifest["project"]
    routes = []
    for svc_name, svc in manifest.get("services", {}).items():
        alias = f"{project}-{svc_name}"
        port = svc["port"]
        for route in svc.get("routes", []):
            if isinstance(route, dict):
                path = route.get("path", "/")
            elif isinstance(route, str):
                path = route
            else:
                continue
            routes.append((path, alias, port))

    # Sort: longer/more specific paths first, then alphabetical
    routes.sort(key=lambda r: (-len(r[0]), r[0]))
    return routes
