"""Tests for manifest migration chain."""

import pytest

from boxmunge.migration import (
    MigrationError,
    _MIGRATIONS,
    get_migration_path,
    migrate_manifest,
    register_migration,
)


# Snapshot the canonical migrations at module load — BEFORE any test runs and
# could pollute the registry. This is the order-independent baseline the
# autouse fixture restores to between tests.
_CANONICAL_MIGRATIONS = dict(_MIGRATIONS)


@pytest.fixture(autouse=True)
def clean_migrations():
    """Reset migration registry to the canonical baseline between tests.

    Order-independent: each test starts and ends with exactly the migrations
    that boxmunge.migration registers at import time. A test that registers
    a bad migration cannot leak it into a later test, even if it crashes
    before its own cleanup runs.
    """
    _MIGRATIONS.clear()
    _MIGRATIONS.update(_CANONICAL_MIGRATIONS)
    yield
    _MIGRATIONS.clear()
    _MIGRATIONS.update(_CANONICAL_MIGRATIONS)


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
        # Use a target version far beyond any real registration to guarantee
        # a missing step regardless of which v0.x migrations are registered.
        register_migration(1, 2, lambda m: m)
        with pytest.raises(MigrationError, match="No migration path"):
            get_migration_path(1, 99)

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


class TestV1toV2Migration:
    def test_v1_no_security_block_becomes_v2(self) -> None:
        v1 = {
            "schema_version": 1,
            "project": "demo",
            "services": {"web": {"port": 3000}},
        }
        result = migrate_manifest(v1, target_version=2)
        assert result["schema_version"] == 2
        # Manifest is otherwise unchanged
        assert result["project"] == "demo"
        assert result["services"] == {"web": {"port": 3000}}
        # No injected security block — defaults are silent
        assert "security" not in result

    def test_implicit_v1_default_migrates(self) -> None:
        # Manifest with no schema_version is treated as v1.
        v1 = {"project": "demo", "services": {"web": {"port": 3000}}}
        result = migrate_manifest(v1, target_version=2)
        assert result["schema_version"] == 2


class TestFixtureOrderIndependence:
    """F6: clean_migrations restores canonical baseline regardless of pollution."""

    def test_v1_to_v2_intact_after_pollution(self) -> None:
        """Even if a previous test registered a bad (1,2) and crashed before
        cleanup, this test must still see the real _migrate_v1_to_v2.
        """
        # Simulate pollution: overwrite (1,2) with a non-canonical lambda.
        # The autouse fixture cleared+restored at the start of THIS test, so
        # we have the real migration. Pollute it now (mid-test) and verify
        # the next test (next call) gets the canonical one back.
        register_migration(1, 2, lambda m: {**m, "polluted": True})

        # If we were to run another test now, the autouse fixture's
        # post-yield reset would put _CANONICAL_MIGRATIONS back. Verify the
        # canonical migration is still in the snapshot:
        assert (1, 2) in _CANONICAL_MIGRATIONS
        # And the pollution is visible NOW:
        result = migrate_manifest({"schema_version": 1}, target_version=2)
        assert result.get("polluted") is True

    def test_subsequent_test_sees_canonical_migration(self) -> None:
        """This test runs AFTER test_v1_to_v2_intact_after_pollution.
        Despite that test polluting the (1,2) registration mid-flight, this
        test must see the REAL _migrate_v1_to_v2 — no 'polluted' field.
        """
        result = migrate_manifest(
            {"schema_version": 1, "project": "demo"}, target_version=2
        )
        assert result["schema_version"] == 2
        assert "polluted" not in result, (
            "Migration registry leaked from a previous test — fixture is "
            "not order-independent."
        )
