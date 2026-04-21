"""Tests for platform stash — captures state for safe upgrades."""

import json
import tarfile
from pathlib import Path

import pytest
import yaml

from boxmunge.stash import create_stash, list_stashes, prune_stashes, restore_stash
from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version


def _setup_project(paths: BoxPaths, name: str) -> None:
    """Create a minimal deployed project for stash testing."""
    project_dir = paths.project_dir(name)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": name,
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (project_dir / "secrets.env").write_text("SECRET=value\n")

    state_dir = paths.deploy_state
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / f"{name}.json").write_text(json.dumps({
        "current_ref": "abc123", "deployed_at": "2026-04-15T10:00:00Z",
    }))


class TestCreateStash:
    def test_creates_archive(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)
        assert archive.exists()
        assert archive.name.startswith("boxmunge-stash-")
        assert archive.name.endswith(".tar.gz")

    def test_archive_contains_project_files(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        assert any("myapp/manifest.yml" in n for n in names)
        assert any("myapp/compose.yml" in n for n in names)
        assert any("boxmunge.yml" in n for n in names)

    def test_archive_contains_version(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        assert any("version" in n for n in names)


class TestListStashes:
    def test_lists_by_date_descending(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        (paths.stashes / "boxmunge-stash-2026-04-14T100000.tar.gz").write_text("")
        (paths.stashes / "boxmunge-stash-2026-04-15T100000.tar.gz").write_text("")
        stashes = list_stashes(paths)
        assert len(stashes) == 2
        assert "2026-04-15" in stashes[0].name

    def test_empty_when_none(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        assert list_stashes(paths) == []


class TestPruneStashes:
    def test_keeps_n_most_recent(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        for i in range(5):
            (paths.stashes / f"boxmunge-stash-2026-04-{10+i}T100000.tar.gz").write_text("")
        pruned = prune_stashes(paths, keep=3)
        assert len(pruned) == 2
        remaining = list_stashes(paths)
        assert len(remaining) == 3


class TestRestoreStash:
    def test_restore_recovers_config(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        archive = create_stash(paths)

        # Corrupt config to verify restore fixes it
        paths.config_file.write_text("hostname: corrupted\n")
        (paths.project_manifest("myapp")).write_text("corrupted: true\n")

        restore_stash(paths, archive)

        assert "hostname: test" in paths.config_file.read_text()
        assert "schema_version" in paths.project_manifest("myapp").read_text()

    def test_restore_latest(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        create_stash(paths)  # older
        import time; time.sleep(0.1)
        paths.config_file.write_text("hostname: latest\nadmin_email: t@t\n")
        latest = create_stash(paths)  # newer

        paths.config_file.write_text("hostname: corrupted\n")
        restore_stash(paths)  # no archive arg = latest

        assert "hostname: latest" in paths.config_file.read_text()

    def test_restore_nonexistent_raises(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        with pytest.raises(FileNotFoundError):
            restore_stash(paths, tmp_path / "nope.tar.gz")

    def test_restore_no_stashes_raises(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.stashes.mkdir(parents=True)
        with pytest.raises(FileNotFoundError):
            restore_stash(paths)
