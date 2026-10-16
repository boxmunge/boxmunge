# SPDX-License-Identifier: Apache-2.0
"""Tests for boxmunge.commands.upgrade_steps internals."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.upgrade_steps import migrate_project_manifests
from boxmunge.manifest import (
    CURRENT_SCHEMA_VERSION, ManifestError, load_manifest_as_written,
)
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

        migrated = migrate_project_manifests(paths_stub)

        assert migrated.written == ["demo"]
        assert migrated.in_memory == []
        on_disk = yaml.safe_load(mf.read_text())
        # migrate_project_manifests migrates to CURRENT_SCHEMA_VERSION, which
        # rolls forward with every release. Pin against the manifest module to
        # avoid this test needing edits on every schema bump.
        from boxmunge.manifest import CURRENT_SCHEMA_VERSION
        assert on_disk["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_post_migration_validation_failure_raises(
        self, paths_stub
    ) -> None:
        """If a migration produces an invalid manifest, migrate_project_manifests
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
                migrate_project_manifests(paths_stub)

            # On-disk manifest must be unchanged.
            assert mf.read_text() == original_text
        finally:
            if original_v1_to_v2 is not None:
                register_migration(1, 2, original_v1_to_v2)


class TestMigrateFailLoud:
    """4a: per-project ManifestError/MigrationError must propagate, not be silently skipped.

    A corrupted manifest or a migrate_manifest failure means the project never
    gets its schema bumped or overlay regenerated. Continuing past such a
    failure would let the upgrade report success while leaving stale state on
    disk; the shim relies on a non-zero exit to trigger rollback.
    """

    def test_corrupted_manifest_raises_manifest_error(self, paths_stub) -> None:
        """A project whose manifest is not a YAML mapping must cause
        migrate_project_manifests to raise ManifestError (was: silently
        skipped)."""
        proj = paths_stub.projects / "broken"
        proj.mkdir(parents=True)
        # Valid YAML but not a mapping — load_manifest raises ManifestError.
        (proj / "manifest.yml").write_text("- just\n- a\n- list\n")

        with pytest.raises(ManifestError, match="not a YAML mapping"):
            migrate_project_manifests(paths_stub)

    def test_migrate_manifest_failure_raises(self, paths_stub) -> None:
        """A project where migrate_manifest itself raises must propagate the
        MigrationError (was: caught + continue, project silently skipped)."""
        original_v1_to_v2 = _MIGRATIONS.get((1, 2))

        def raising_v1_to_v2(manifest):
            raise MigrationError("simulated migration failure")

        register_migration(1, 2, raising_v1_to_v2)
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
            _write_manifest(paths_stub, "demo", v1)

            with pytest.raises(MigrationError, match="simulated migration failure"):
                migrate_project_manifests(paths_stub)
        finally:
            if original_v1_to_v2 is not None:
                register_migration(1, 2, original_v1_to_v2)


class TestGitManifestNeverWritten:
    """D19: a git project's manifest.yml links into repo/. It is migrated in
    memory by every reader; the upgrade never writes it, and alerts once."""

    V2 = {
        "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "git", "repo": "https://example.com/gitapp.git",
        "project": "gitapp", "hosts": ["gitapp.example.com"],
        "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
    }

    @pytest.fixture
    def linked(self, paths) -> Path:
        repo = paths.project_dir("gitapp") / "repo"
        repo.mkdir(parents=True)
        target = repo / "manifest.yml"
        target.write_text(yaml.safe_dump(self.V2))
        paths.project_manifest("gitapp").symlink_to(target)
        return target

    def _migrate(self, paths, delivered: bool = True):
        with patch("boxmunge.manifest_schema_alert.notify",
                   return_value=delivered) as notify:
            result = migrate_project_manifests(paths)
        return result, notify

    def test_link_is_kept_and_alert_sent(self, paths, linked) -> None:
        before = linked.read_bytes()
        result, notify = self._migrate(paths)
        assert (result.written, result.in_memory) == ([], ["gitapp"])
        link = paths.project_manifest("gitapp")
        assert link.is_symlink() and link.resolve() == linked.resolve()
        assert linked.read_bytes() == before
        notify.assert_called_once()
        assert "schema 2" in notify.call_args.args[2]
        assert "gitapp: the repository's manifest.yml uses schema 2" in paths.log_file.read_text()

    def test_alerts_once(self, paths, linked) -> None:
        self._migrate(paths)
        _, notify = self._migrate(paths)
        notify.assert_not_called()

    def test_undelivered_alert_is_retried(self, paths, linked) -> None:
        self._migrate(paths, delivered=False)
        assert not paths.manifest_schema_alert_state("gitapp").exists()
        _, notify = self._migrate(paths)
        notify.assert_called_once()

    def test_new_current_schema_alerts_again(self, paths, linked) -> None:
        record = paths.manifest_schema_alert_state("gitapp")
        record.parent.mkdir(parents=True)
        record.write_text(json.dumps({"repository_schema": 2,
                                      "current_schema": CURRENT_SCHEMA_VERSION - 1}))
        _, notify = self._migrate(paths)
        notify.assert_called_once()

    def test_unreadable_record_is_reported_and_replaced(self, paths, linked) -> None:
        record = paths.manifest_schema_alert_state("gitapp")
        record.parent.mkdir(parents=True)
        record.write_text("{not json")
        _, notify = self._migrate(paths)
        notify.assert_called_once()
        assert "is unreadable" in paths.log_file.read_text()
        assert json.loads(record.read_text())["repository_schema"] == 2

    def test_regular_manifest_is_still_written(self, paths) -> None:
        pdir = paths.project_dir("bundled")
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(yaml.safe_dump(
            {**self.V2, "source": "bundle", "project": "bundled"}))
        result, notify = self._migrate(paths)
        assert result.written == ["bundled"]
        notify.assert_not_called()
        on_disk = load_manifest_as_written(pdir / "manifest.yml")
        assert on_disk["schema_version"] == CURRENT_SCHEMA_VERSION
