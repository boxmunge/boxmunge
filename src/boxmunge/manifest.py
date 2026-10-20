# SPDX-License-Identifier: Apache-2.0
"""Load and validate project manifests (manifest.yml)."""

from pathlib import Path
from typing import Any

import yaml

from boxmunge.backup_command_warnings import backup_command_warnings
from boxmunge.fileutil import LinkedTargetError, atomic_write_text
from boxmunge.manifest_fields import (
    SERVICE_NAME_RE, deploy_problems, host_problem, port_problem, route_path_problem,
)
from boxmunge.migration import MigrationError, migrate_manifest
from boxmunge.user_entries import (
    USER_ENTRIES, is_user_entry, split_user_entries, user_entry_problems,
)

CURRENT_SCHEMA_VERSION = 3


class ManifestError(Exception):
    """Raised when a manifest file cannot be loaded."""


def load_manifest_as_written(path: Path) -> dict[str, Any]:
    """Load a manifest.yml file exactly as written, without migrating it.

    For checking the file an author wrote (validation, rewriting a source
    manifest) and for the upgrade's on-disk migration. Everything else
    reads through load_manifest.

    Raises ManifestError, naming the file, if it doesn't exist, can't be
    read, or can't be parsed.
    """
    if not path.exists():
        raise ManifestError(f"Manifest not found: {path}")

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ManifestError(f"Manifest is not valid YAML: {path}: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        raise ManifestError(f"Cannot read manifest {path}: {e}") from e

    if not isinstance(data, dict):
        raise ManifestError(f"Manifest is not a YAML mapping: {path}")

    return data


def at_current_schema(manifest: dict[str, Any], path: Path) -> dict[str, Any]:
    """The manifest migrated in memory to CURRENT_SCHEMA_VERSION.

    A git project's manifest.yml is a link into its checkout, which the
    upgrade never rewrites, so it can stay at an older schema indefinitely.
    A schema_version that is not a supported integer is returned unchanged
    for validate_manifest to report, and an absent one stays absent: readers
    that need it refuse to guess (security_cmd).
    """
    version = manifest.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int):
        return manifest
    if not 1 <= version <= CURRENT_SCHEMA_VERSION:
        return manifest
    try:
        current = migrate_manifest(manifest, CURRENT_SCHEMA_VERSION)
    except MigrationError as e:
        raise ManifestError(f"Cannot migrate manifest {path}: {e}") from e
    return split_user_entries(current)


def load_manifest(path: Path) -> dict[str, Any]:
    """Load a manifest.yml file at the current schema (see at_current_schema).

    Raises ManifestError, naming the file, if it doesn't exist, can't be
    read, parsed or migrated.
    """
    return at_current_schema(load_manifest_as_written(path), path)


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    """Atomically replace a regular manifest.yml with `manifest`.

    Refuses a symlink: a git project's manifest.yml links into its checkout,
    and renaming a file over the link would silently detach the project from
    its repository's manifest. Writing through the link is no better: the
    checkout is the repository's content, which the next checkout overwrites
    or conflicts with. The link is checked again right before the rename
    (see atomic_write_bytes for the window that remains).
    """
    refusal = (f"{path} is a symlink (a git project's manifest.yml links into "
               f"its repository); refusing to replace it. Change the manifest in "
               f"the repository instead.")
    if path.is_symlink():
        raise ManifestError(refusal)
    try:
        atomic_write_text(path, yaml.dump(manifest, default_flow_style=False, sort_keys=False),
                          refuse_link=True)
    except LinkedTargetError as e:
        raise ManifestError(refusal) from e


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
    if USER_ENTRIES in manifest:
        errors.append(f"'{USER_ENTRIES}' is boxmunge's own name for the user-only service "
                      f"entries; write those under services:")

    # Schema version check
    schema_version = manifest.get("schema_version", 1)
    # bool is a subclass of int: `schema_version: true` must not pass as 1.
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        errors.append(
            f"schema_version must be an unquoted integer from 1 to "
            f"{CURRENT_SCHEMA_VERSION}, got {schema_version!r}. Write it as, "
            f"for example, schema_version: {CURRENT_SCHEMA_VERSION}."
        )
        return errors, warnings  # Can't validate further
    if schema_version < 1 or schema_version > CURRENT_SCHEMA_VERSION:
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
            problem = host_problem(entry)
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
            if not isinstance(svc_name, str) or not SERVICE_NAME_RE.fullmatch(svc_name):
                errors.append(f"Service name '{svc_name}' is invalid. Must be lowercase alphanumeric with hyphens.")
            if not isinstance(svc, dict):
                errors.append(f"Service '{svc_name}' must be a mapping.")
                continue
            if is_user_entry(svc) and "security" in svc:
                errors += user_entry_problems(svc_name, svc)
                continue
            routes = svc.get("routes", [])
            if "internal" in svc and not isinstance(svc["internal"], bool):
                errors.append(f"Service '{svc_name}' internal must be true or false.")
            # An internal service (database, cache, worker) may be declared only
            # to give it a read-only rootfs and writable: paths; it needs no route.
            routeless = svc.get("internal") is True and not routes
            if "port" in svc:
                problem = port_problem(svc["port"])
                if problem:
                    errors.append(f"Service '{svc_name}' port {problem}.")
            elif not routeless:
                errors.append(f"Service '{svc_name}' is missing 'port'.")
            if not routes:
                if not routeless:
                    errors.append(
                        f"Service '{svc_name}' must have at least one route, or "
                        f"set internal: true for a service Caddy does not route to."
                    )
            elif not isinstance(routes, list):
                errors.append(f"Service '{svc_name}' routes must be a list.")
            else:
                for i, route in enumerate(routes):
                    if not isinstance(route, dict) or "path" not in route:
                        errors.append(
                            f"Service '{svc_name}' route {i}: must be "
                            f"a mapping with 'path' key, e.g. {{path: /}}, "
                            f"got: {route!r}"
                        )
                        continue
                    path = route["path"]
                    problem = route_path_problem(path)
                    if problem:
                        errors.append(
                            f"Service '{svc_name}' route {i}: path "
                            f"{path!r} {problem}."
                        )
                    elif path != "/" and path.endswith("/"):
                        warnings.append(
                            f"Service '{svc_name}' route {i}: path {path!r} is an "
                            f"exact match in Caddy, so requests below it go to "
                            f"another route. Use {path + '*'!r} to route them here."
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

    # Writable: block — per-service, optional. Requires schema_version 3.
    # Lazy import keeps writable as an independent module without circular dep.
    from boxmunge.writable import (
        WritableValidationError,
        validate_writable_block,
    )

    has_any_writable_block = any(
        isinstance(svc, dict) and svc.get("writable") is not None
        for svc in services.values()
    )
    if has_any_writable_block and schema_version < 3:
        errors.append(
            f"manifest declares a 'writable:' block but schema_version is "
            f"{schema_version}. The 'writable:' block requires schema_version: 3 "
            f"(boxmunge 0.9.0+). Bump schema_version to 3 — manifests without a "
            f"'writable:' block are unchanged by the bump."
        )
    else:
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            writable_block = svc.get("writable")
            try:
                validate_writable_block(writable_block, service_name=svc_name)
            except WritableValidationError as e:
                errors.append(str(e))

        # Project-wide uniqueness: persistent volume names emit
        # <project>_<name> docker volumes, so two services declaring the
        # same `name` would alias to the same volume. Catch at manifest
        # time rather than letting Compose silently share the mount.
        seen_volume_names: dict[str, str] = {}
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            writable_block = svc.get("writable")
            if not isinstance(writable_block, dict):
                continue
            persistent = writable_block.get("persistent")
            if not isinstance(persistent, list):
                continue
            for entry in persistent:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                if not isinstance(name, str):
                    continue
                prior_svc = seen_volume_names.get(name)
                if prior_svc is not None and prior_svc != svc_name:
                    errors.append(
                        f"writable.persistent name {name!r} is declared "
                        f"by both services.{prior_svc!r} and "
                        f"services.{svc_name!r}. Names must be unique "
                        f"project-wide because the generated docker "
                        f"volume name is <project>_<name>."
                    )
                seen_volume_names[name] = svc_name

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
        # Service resolvability. An unset backup.service is only safe to
        # infer when the manifest defines exactly one service; otherwise the
        # backup would silently target the wrong (or a non-existent)
        # container. Fail at deploy time rather than swallow it as a runtime
        # warning that defeats pre-deploy snapshots.
        if not backup.get("service") and len(services) != 1:
            errors.append(
                f"Backup is configured but 'backup.service' is not set and the "
                f"manifest defines {len(services)} services. Set "
                f"'backup.service' to the compose service the dump/restore "
                f"command runs in."
            )
        warnings.extend(backup_command_warnings(backup))

    errors.extend(deploy_problems(manifest.get("deploy", {})))

    # Smoke tests — per-service
    has_any_smoke = any(
        isinstance(svc, dict) and svc.get("smoke") for svc in services.values()
    )
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
        errors.extend(_copy_data_errors(staging.get("copy_data")))

    return errors, warnings


def _copy_data_errors(copy_data: Any) -> list[str]:
    """`copy_data` is a boolean, or {sources: {staged store: production store or null}}."""
    if copy_data is None or isinstance(copy_data, bool):
        return []
    shape = ("Use true, or {sources: {<staged store>: <production store or null>}}; "
             "a store is a compose volume key, a writable.persistent name, or ./path.")
    if not isinstance(copy_data, dict) or set(copy_data) != {"sources"}:
        return [f"'staging.copy_data' must be a boolean or a mapping with only "
                f"'sources'. {shape}"]
    sources = copy_data["sources"]
    if not isinstance(sources, dict) or not sources or not all(
        isinstance(k, str) and k and (v is None or (isinstance(v, str) and v))
        for k, v in sources.items()
    ):
        return [f"'staging.copy_data.sources' must map store names to store names "
                f"or null. {shape}"]
    return []


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
        if not svc.get("routes"):
            continue  # an internal service declared without routes
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
