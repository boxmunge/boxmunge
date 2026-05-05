# SPDX-License-Identifier: Apache-2.0
"""Tests for boxmunge.commands.upgrade_cmd internals."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge.commands.upgrade_cmd import _migrate_project_manifests
from boxmunge.migration import (
    MigrationError, register_migration, _MIGRATIONS,
)


@pytest.fixture
def paths_stub(tmp_path, monkeypatch):
    """Minimal BoxPaths stub pointing at tmp_path/projects."""
    from boxmunge.paths import BoxPaths
    monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
    paths = BoxPaths()
    paths.projects = tmp_path / "projects"
    paths.projects.mkdir(parents=True)
    paths.logs = tmp_path / "logs"
    paths.logs.mkdir()
    paths.log_file = paths.logs / "boxmunge.log"
    return paths


def _write_manifest(paths_stub, name: str, manifest: dict) -> Path:
    proj = paths_stub.projects / name
    proj.mkdir(parents=True, exist_ok=True)
    mf = proj / "manifest.yml"
    mf.write_text(yaml.safe_dump(manifest))
    return mf


class TestMigratePostValidation:
    """F2: post-migration validation prevents persisting malformed manifests."""

    def test_valid_v1_to_v2_migrates_and_writes(self, paths_stub) -> None:
        v1 = {
            "schema_version": 1,
            "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "source": "bundle",
            "project": "demo",
            "hosts": ["demo.example.com"],
            "services": {
                "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
            },
        }
        mf = _write_manifest(paths_stub, "demo", v1)

        migrated = _migrate_project_manifests(paths_stub)

        assert migrated == ["demo"]
        on_disk = yaml.safe_load(mf.read_text())
        assert on_disk["schema_version"] == 2

    def test_post_migration_validation_failure_raises(
        self, paths_stub
    ) -> None:
        """If a migration produces an invalid manifest, _migrate_project_manifests
        must raise MigrationError and leave the original manifest on disk."""

        # Inject a bad migration that produces an invalid manifest
        # (drops the required 'project' field). Restore in finally.
        original_v1_to_v2 = _MIGRATIONS.get((1, 2))

        def bad_v1_to_v2(manifest):
            result = dict(manifest)
            result["schema_version"] = 2
            del result["project"]  # makes manifest invalid
            return result

        register_migration(1, 2, bad_v1_to_v2)
        try:
            v1 = {
                "schema_version": 1,
                "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
                "source": "bundle",
                "project": "demo",
                "hosts": ["demo.example.com"],
                "services": {
                    "web": {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"},
                },
            }
            original_text = yaml.safe_dump(v1)
            mf = _write_manifest(paths_stub, "demo", v1)

            with pytest.raises(MigrationError, match="failed validation"):
                _migrate_project_manifests(paths_stub)

            # On-disk manifest must be unchanged.
            assert mf.read_text() == original_text
        finally:
            if original_v1_to_v2 is not None:
                register_migration(1, 2, original_v1_to_v2)
