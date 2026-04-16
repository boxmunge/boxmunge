"""Tests for manifest migration chain."""

import pytest

from boxmunge.migration import (
    MigrationError,
    _MIGRATIONS,
    get_migration_path,
    migrate_manifest,
    register_migration,
)


@pytest.fixture(autouse=True)
def clean_migrations():
    """Reset migration registry between tests."""
    saved = dict(_MIGRATIONS)
    yield
    _MIGRATIONS.clear()
    _MIGRATIONS.update(saved)


class TestMigrationPath:
    def test_no_migration_needed(self) -> None:
        path = get_migration_path(1, 1)
        assert path == []

    def test_single_step(self) -> None:
        register_migration(1, 2, lambda m: {**m, "new_field": True})
        path = get_migration_path(1, 2)
        assert path == [(1, 2)]

    def test_multi_step(self) -> None:
        register_migration(1, 2, lambda m: m)
        register_migration(2, 3, lambda m: m)
        path = get_migration_path(1, 3)
        assert path == [(1, 2), (2, 3)]

    def test_missing_step_raises(self) -> None:
        register_migration(1, 2, lambda m: m)
        with pytest.raises(MigrationError, match="No migration path"):
            get_migration_path(1, 3)

    def test_downgrade_raises(self) -> None:
        with pytest.raises(MigrationError, match="Cannot downgrade"):
            get_migration_path(2, 1)


class TestMigrateManifest:
    def test_applies_transform(self) -> None:
        register_migration(
            1, 2, lambda m: {**m, "schema_version": 2, "migrated": True}
        )
        manifest = {"schema_version": 1, "project": "test"}
        result = migrate_manifest(manifest, target_version=2)
        assert result["schema_version"] == 2
        assert result["migrated"] is True
        assert result["project"] == "test"

    def test_applies_chain(self) -> None:
        register_migration(
            1, 2, lambda m: {**m, "schema_version": 2, "step1": True}
        )
        register_migration(
            2, 3, lambda m: {**m, "schema_version": 3, "step2": True}
        )
        manifest = {"schema_version": 1, "project": "test"}
        result = migrate_manifest(manifest, target_version=3)
        assert result["schema_version"] == 3
        assert result["step1"] is True
        assert result["step2"] is True

    def test_no_op_when_current(self) -> None:
        manifest = {"schema_version": 1, "project": "test"}
        result = migrate_manifest(manifest, target_version=1)
        assert result == manifest

    def test_defaults_missing_schema_version_to_1(self) -> None:
        register_migration(1, 2, lambda m: {**m, "schema_version": 2})
        manifest = {"project": "test"}
        result = migrate_manifest(manifest, target_version=2)
        assert result["schema_version"] == 2
