# SPDX-License-Identifier: Apache-2.0
"""Load manifest.yml and check the shape the client relies on.

The server is the only authority on manifest policy (hosts, routes, backup,
security:, writable:, schema rules): it validates every bundle on stage and
prod-deploy before it changes anything. A vendored copy of those rules
drifted from the server and accepted manifests the server rejects, so the
client no longer carries one. It checks only what it needs to build, name
and route a bundle, and never raises on a malformed shape:

  - the document is a mapping;
  - schema_version, if present, is a positive integer (the handshake
    compares it with the server's before upload);
  - id (unless bundle is about to add it), project and source are present,
    and project is a valid project name, because it names the bundle file;
  - hosts is a non-empty list of strings, without init's placeholder;
  - services is a non-empty mapping of name -> mapping.

`stage --dry-run` / `prod-deploy --dry-run` run the server's full
validation without deploying.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

# The server's project-name rule (src/boxmunge/paths.py); used with fullmatch.
_VALID_PROJECT_NAME = re.compile(r"[a-z0-9][a-z0-9\-]{0,62}")

# init scaffolds this until the user names a real host; bundling refuses it.
PLACEHOLDER_HOST_SUFFIX = ".change-me.invalid"
# The server's host rule (src/boxmunge/manifest.py _HOST_LABEL_RE), for init --host.
_HOST_RE = re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")


def placeholder_host(project: str) -> str:
    return f"{project}{PLACEHOLDER_HOST_SUFFIX}"


def valid_host(host: str) -> bool:
    return bool(_HOST_RE.fullmatch(host))


class ManifestError(Exception):
    """Raised when a manifest file cannot be loaded."""


def load_manifest(path: Path) -> dict[str, Any]:
    """Load manifest.yml. Raises ManifestError if missing, unparseable or not a mapping."""
    if not path.exists():
        raise ManifestError(f"Manifest not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ManifestError(f"{path} is not valid YAML: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        raise ManifestError(f"Cannot read {path}: {e}") from e
    if not isinstance(data, dict):
        raise ManifestError(f"Manifest is not a YAML mapping: {path}")
    return data


def _check_schema(manifest: dict[str, Any]) -> list[str]:
    schema = manifest.get("schema_version", 1)
    # YAML 1.1 parses unquoted yes/no/on/off/true/false as booleans, and bool
    # is an int in Python: reject it explicitly.
    if isinstance(schema, bool):
        return [f"schema_version parsed as boolean {schema}: it must be an integer, "
                "e.g. schema_version: 3."]
    if not isinstance(schema, int) or schema < 1:
        return [f"Invalid schema_version {schema!r}: expected an integer >= 1."]
    return []


def _check_identity(manifest: dict[str, Any], require_id: bool) -> list[str]:
    errors = []
    project = manifest.get("project")
    if not project:
        errors.append("Required field 'project' is missing.")
    elif not isinstance(project, str) or not _VALID_PROJECT_NAME.fullmatch(project):
        errors.append(f"Invalid 'project' {project!r}: must be lowercase alphanumeric "
                      "with hyphens, 1-63 chars.")
    project_id = manifest.get("id")
    if require_id and not project_id:
        errors.append("Required field 'id' is missing. "
                      "Run 'boxmunge bundle' without --validate to add one.")
    if not manifest.get("source"):
        errors.append("Required field 'source' is missing. Specify 'source: bundle'.")
    return errors


def _check_hosts(manifest: dict[str, Any]) -> list[str]:
    hosts = manifest.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        return ["'hosts' must be a list with at least one hostname."]
    errors = []
    for host in hosts:
        if not isinstance(host, str):
            errors.append(f"hosts: {host!r} is not a string.")
        elif host.endswith(PLACEHOLDER_HOST_SUFFIX):
            errors.append(f"hosts: {host!r} is the scaffold's change-me placeholder. "
                          "Set the real hostname this project serves.")
    return errors


def _check_services(manifest: dict[str, Any]) -> list[str]:
    services = manifest.get("services")
    if not isinstance(services, dict) or not services:
        return ["'services' must be a mapping with at least one service."]
    return [f"Service {name!r} must be a mapping, got {type(svc).__name__}."
            for name, svc in services.items() if not isinstance(svc, dict)]


def validate_manifest(
    manifest: Any, require_id: bool = True
) -> tuple[list[str], list[str]]:
    """Check the manifest's shape (see the module docstring).

    require_id=False when the caller is about to add a missing id. Returns
    (errors, warnings); never raises on a malformed manifest.
    """
    if not isinstance(manifest, dict):
        return ["manifest.yml must be a YAML mapping at the top level."], []
    errors = _check_schema(manifest)
    errors += _check_identity(manifest, require_id)
    errors += _check_hosts(manifest)
    errors += _check_services(manifest)
    return errors, []
