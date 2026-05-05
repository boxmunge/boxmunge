"""Tests for platform stash — captures state for safe upgrades."""

import io
import json
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.stash import (
    STASH_FORMAT_VERSION,
    StashError,
    create_stash,
    list_stashes,
    prune_stashes,
    restore_stash,
)
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

    def test_does_not_chmod_existing_dir(self, tmp_path: Path) -> None:
        """Regression: stash.create_stash must not chmod the dir.

        On real installs the stashes dir is owned by root with the deploy user
        in the group. A chmod from deploy context fails with EPERM and aborts
        the upgrade. We rely on install.sh to set perms once."""
        import os
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "logs"]:
            (paths.root / d).mkdir(parents=True)
        paths.stashes.mkdir(parents=True)
        os.chmod(paths.stashes, 0o770)
        (paths.config_file).write_text("hostname: test\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")

        before = paths.stashes.stat().st_mode & 0o777
        create_stash(paths)
        after = paths.stashes.stat().st_mode & 0o777
        assert before == after == 0o770

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


def _make_paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
        (paths.root / d).mkdir(parents=True)
    return paths


def _build_malicious_archive(
    archive_path: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
    include_meta: bool = True,
) -> None:
    """Build a tarball with arbitrary members for traversal/symlink tests."""
    with tarfile.open(archive_path, "w:gz") as tar:
        if include_meta:
            payload = json.dumps({
                "format_version": STASH_FORMAT_VERSION,
                "platform_version": "test",
                "created_at": "2026-05-05T00:00:00+00:00",
            }).encode()
            info = tarfile.TarInfo(name="boxmunge-stash-meta.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        for info, data in members:
            if data is None:
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))


class TestStashTraversalGuards:
    def test_rejects_dotdot_segment(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "malicious.tar.gz"
        info = tarfile.TarInfo(name="config/../../etc/evil")
        _build_malicious_archive(archive, [(info, b"pwn")])
        with pytest.raises(StashError, match="suspicious"):
            restore_stash(paths, archive)

    def test_rejects_absolute_path(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "malicious.tar.gz"
        info = tarfile.TarInfo(name="/etc/evil")
        _build_malicious_archive(archive, [(info, b"pwn")])
        with pytest.raises(StashError, match="suspicious"):
            restore_stash(paths, archive)

    def test_allows_dotdot_substring_in_name(self, tmp_path: Path) -> None:
        """foo..bar (no path separator) should not trigger guard."""
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "ok.tar.gz"
        info = tarfile.TarInfo(name="config/foo..bar")
        _build_malicious_archive(archive, [(info, b"hello")])
        # Should restore without raising
        restore_stash(paths, archive)
        assert (paths.config / "foo..bar").read_bytes() == b"hello"

    def test_rejects_symlink_member(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "symlink.tar.gz"
        info = tarfile.TarInfo(name="config/evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        _build_malicious_archive(archive, [(info, None)])
        with pytest.raises(StashError):
            restore_stash(paths, archive)


class TestStashAtomicWrites:
    def test_rename_failure_keeps_target_intact(self, tmp_path: Path) -> None:
        """When os.rename fails mid-restore, original target file untouched."""
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: original\nadmin_email: t@t\n")
        write_installed_version(paths, "0.2.0", "abc1234")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)

        # Mutate target so restore would change it
        paths.config_file.write_text("hostname: corrupt\n")

        with patch("boxmunge.fileutil.os.rename", side_effect=OSError("simulated SIGKILL")):
            with pytest.raises(OSError):
                restore_stash(paths, archive)

        # Target intact (still corrupt content, not partial bytes)
        assert paths.config_file.read_text() == "hostname: corrupt\n"
        # No leftover temp files
        temps = list(paths.config.glob(".*tmp"))
        assert temps == []


class TestStashSchemaVersion:
    def test_create_writes_meta_file(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
            assert "boxmunge-stash-meta.json" in names
            extracted = tar.extractfile("boxmunge-stash-meta.json")
            assert extracted is not None
            meta = json.loads(extracted.read())
        assert meta["format_version"] == STASH_FORMAT_VERSION
        assert meta["platform_version"] == "0.5.3+deadbee"
        assert "created_at" in meta

    def test_restore_with_current_version(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)
        # Should restore without raising
        restore_stash(paths, archive)

    def test_restore_with_newer_version_raises(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "future.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            payload = json.dumps({
                "format_version": STASH_FORMAT_VERSION + 1,
                "platform_version": "9.9.9",
                "created_at": "2099-01-01T00:00:00+00:00",
            }).encode()
            info = tarfile.TarInfo(name="boxmunge-stash-meta.json")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        with pytest.raises(StashError, match="newer than this installation"):
            restore_stash(paths, archive)

    def test_restore_legacy_no_meta_warns(self, tmp_path: Path) -> None:
        """Legacy stashes (created before meta file existed) restore w/ warning."""
        paths = _make_paths(tmp_path)
        archive = paths.stashes / "legacy.tar.gz"
        # Build a legacy-format stash (no meta file) using direct tarfile
        with tarfile.open(archive, "w:gz") as tar:
            payload = b"hostname: legacy\nadmin_email: t@t\n"
            info = tarfile.TarInfo(name="config/boxmunge.yml")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))

        with patch("boxmunge.stash.log_warning") as mock_warn:
            restore_stash(paths, archive)
        assert mock_warn.called
        # Verify the warning mentions absent format marker
        call_args = mock_warn.call_args
        assert "format_version" in call_args.args[1] or "format_version" in str(call_args)
        # And the file actually got restored
        assert paths.config_file.read_text() == "hostname: legacy\nadmin_email: t@t\n"


class TestStashLogging:
    def test_create_emits_log_operation(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        with patch("boxmunge.stash.log_operation") as mock_log:
            create_stash(paths)
        assert mock_log.called
        # First positional arg is component
        assert mock_log.call_args.args[0] == "stash"
        # Detail should include format_version
        kwargs = mock_log.call_args.kwargs
        assert kwargs.get("detail", {}).get("format_version") == STASH_FORMAT_VERSION

    def test_restore_emits_log_operation(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        (paths.config_file).write_text("hostname: t\nadmin_email: t@t\n")
        write_installed_version(paths, "0.5.3", "deadbee")
        _setup_project(paths, "myapp")
        archive = create_stash(paths)
        with patch("boxmunge.stash.log_operation") as mock_log:
            restore_stash(paths, archive)
        assert mock_log.called
        # Verify "restored" message
        msgs = [c.args[1] for c in mock_log.call_args_list]
        assert any("restored" in m.lower() for m in msgs)
