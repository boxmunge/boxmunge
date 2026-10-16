# SPDX-License-Identifier: Apache-2.0
"""Manifests are migrated in memory on load; the writer never replaces a link.

A git project's manifest.yml is a symlink into its checkout, so an old
schema can never be migrated on disk: every reader migrates it instead,
and writing a manifest over a symlink is refused.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge.manifest import (
    CURRENT_SCHEMA_VERSION, ManifestError, load_manifest,
    load_manifest_as_written, write_manifest,
)

V1 = {
    "schema_version": 1, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "project": "demo",
    "source": "git", "repo": "https://example.com/demo.git",
    "hosts": ["demo.example.com"],
    "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
}


def _write(path: Path, manifest: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    return path


class TestMigrateOnLoad:
    def test_old_schema_is_migrated_in_memory(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "manifest.yml", V1)
        before = path.read_bytes()
        manifest = load_manifest(path)
        assert manifest["schema_version"] == CURRENT_SCHEMA_VERSION
        assert {k: v for k, v in manifest.items() if k != "schema_version"} == {
            k: v for k, v in V1.items() if k != "schema_version"}
        assert path.read_bytes() == before

    def test_absent_schema_version_stays_absent(self, tmp_path: Path) -> None:
        bare = {k: v for k, v in V1.items() if k != "schema_version"}
        path = _write(tmp_path / "manifest.yml", bare)
        assert load_manifest(path) == bare

    def test_through_a_symlink(self, tmp_path: Path) -> None:
        target = _write(tmp_path / "repo" / "manifest.yml", V1)
        link = tmp_path / "manifest.yml"
        link.symlink_to(target)
        assert load_manifest(link)["schema_version"] == CURRENT_SCHEMA_VERSION
        assert link.is_symlink()

    @pytest.mark.parametrize("bad", [True, "2", CURRENT_SCHEMA_VERSION + 1, 0])
    def test_invalid_schema_version_is_left_for_validation(
        self, tmp_path: Path, bad: object,
    ) -> None:
        path = _write(tmp_path / "manifest.yml", {**V1, "schema_version": bad})
        assert load_manifest(path)["schema_version"] == bad

    def test_as_written_is_not_migrated(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "manifest.yml", V1)
        assert load_manifest_as_written(path)["schema_version"] == 1


class TestWriteManifest:
    def test_writes_a_regular_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "manifest.yml", V1)
        write_manifest(path, {**V1, "schema_version": CURRENT_SCHEMA_VERSION})
        assert not path.is_symlink()
        assert load_manifest_as_written(path)["schema_version"] == CURRENT_SCHEMA_VERSION

    def test_refuses_a_symlink(self, tmp_path: Path) -> None:
        target = _write(tmp_path / "repo" / "manifest.yml", V1)
        before = target.read_bytes()
        link = tmp_path / "manifest.yml"
        link.symlink_to(target)
        with pytest.raises(ManifestError, match="is a symlink"):
            write_manifest(link, {**V1, "schema_version": CURRENT_SCHEMA_VERSION})
        assert link.is_symlink()
        assert target.read_bytes() == before
        assert list(tmp_path.glob(".manifest*")) == []

    def test_refuses_a_dangling_symlink(self, tmp_path: Path) -> None:
        link = tmp_path / "manifest.yml"
        link.symlink_to(tmp_path / "repo" / "gone.yml")
        with pytest.raises(ManifestError, match="is a symlink"):
            write_manifest(link, V1)
        assert link.is_symlink()
