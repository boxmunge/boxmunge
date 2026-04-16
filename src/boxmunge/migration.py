# SPDX-License-Identifier: Apache-2.0
"""Manifest migration chain -- ordered transforms between schema versions.

Migrations are registered as (from_version, to_version, transform) tuples.
The engine finds the path from source to target and applies each transform.
"""

from typing import Any, Callable

MigrationTransform = Callable[[dict[str, Any]], dict[str, Any]]

_MIGRATIONS: dict[tuple[int, int], MigrationTransform] = {}


class MigrationError(Exception):
    """Raised when a migration cannot be performed."""


def register_migration(
    from_version: int, to_version: int, transform: MigrationTransform
) -> None:
    """Register a migration transform between two schema versions."""
    _MIGRATIONS[(from_version, to_version)] = transform


def get_migration_path(source: int, target: int) -> list[tuple[int, int]]:
    """Find the ordered migration path from source to target version."""
    if target < source:
        raise MigrationError(
            f"Cannot downgrade manifest from schema_version {source} to {target}"
        )
    if source == target:
        return []

    path = []
    current = source
    while current < target:
        next_version = current + 1
        if (current, next_version) not in _MIGRATIONS:
            raise MigrationError(
                f"No migration path from schema_version {current} to {target}. "
                f"Missing migration: {current} -> {next_version}"
            )
        path.append((current, next_version))
        current = next_version
    return path


def migrate_manifest(manifest: dict[str, Any], target_version: int) -> dict[str, Any]:
    """Migrate a manifest to the target schema version. Returns new dict."""
    source = manifest.get("schema_version", 1)
    path = get_migration_path(source, target_version)
    if not path:
        return dict(manifest)

    result = dict(manifest)
    for from_v, to_v in path:
        transform = _MIGRATIONS[(from_v, to_v)]
        result = transform(result)
    return result
