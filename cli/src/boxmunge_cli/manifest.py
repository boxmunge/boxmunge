# SPDX-License-Identifier: Apache-2.0
"""Load and validate project manifests (manifest.yml)."""

import re
from pathlib import Path
from typing import Any

import yaml

_VALID_SERVICE_NAME = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')


# Highest manifest schema this client has been taught about. The client
# validates only schema-independent basics (project/hosts/services/port/
# routes/id/source) and never inspects schema-gated blocks such as
# `security:` (schema 2) or `writable:` (schema 3) — the server owns those
# and re-validates on receive and deploy. So this is a "what I know about"
# marker for warnings, NOT an upper bound on what may be bundled.
CURRENT_SCHEMA_VERSION = 3


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
    manifest: dict[str, Any], expected_name: str
) -> tuple[list[str], list[str]]:
    """Validate a parsed manifest against the boxmunge project conventions.

    Returns (errors, warnings). errors is empty if the manifest is valid.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Schema version check
    schema_version = manifest.get("schema_version", 1)
    # YAML 1.1 boolean trap: unquoted `yes`/`on`/`true` parse as booleans, and
    # isinstance(True, int) is True in Python — so an unguarded check would
    # silently accept `schema_version: yes` as schema 1 and validate the
    # manifest against the wrong schema. Reject booleans explicitly.
    if isinstance(schema_version, bool):
        errors.append(
            f"schema_version parsed as boolean {schema_version} — it must be "
            f"an integer, e.g. schema_version: 3. YAML parses unquoted "
            f"yes/no/on/off/true/false as booleans."
        )
        return errors, warnings  # Can't validate further
    if not isinstance(schema_version, int) or schema_version < 1:
        errors.append(
            f"Invalid schema_version {schema_version!r}: "
            f"expected an integer >= 1."
        )
        return errors, warnings  # Can't validate further

    if schema_version > CURRENT_SCHEMA_VERSION:
        # Newer than this client knows about. Not an error: the client cannot
        # assess schema-specific validity at all, so failing here would be a
        # false claim of competence and would block a manifest the server
        # accepts. Warn, keep validating the basics, and let the server — the
        # authority on the schema — reject it if it really is unsupported.
        warnings.append(
            f"Manifest declares schema_version {schema_version}, newer than "
            f"this CLI knows about (up to {CURRENT_SCHEMA_VERSION}). "
            f"Local validation is best-effort; the server validates the "
            f"schema authoritatively on deploy. Upgrade the CLI if it "
            f"rejects fields your server supports."
        )

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

    # Services
    services = manifest.get("services", {})
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

    # Backup
    backup = manifest.get("backup", {})
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
