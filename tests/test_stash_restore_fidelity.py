# SPDX-License-Identifier: Apache-2.0
"""C-06: a stash restore (the upgrade rollback) puts files back with their
modes and owners, and leaves lifecycle markers as they are now."""
from __future__ import annotations

import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.stash import StashError, create_stash, restore_stash
from tests.test_stash import _build_malicious_archive, _make_paths, _setup_project


def _as_root(deploy_uid: int, deploy_gid: int):
    deploy = SimpleNamespace(pw_uid=deploy_uid, pw_gid=deploy_gid)
    return (
        patch("boxmunge.stash.os.geteuid", return_value=0),
        patch("boxmunge.stash.pwd.getpwnam", return_value=deploy),
        # Ownership is set on the temp file's descriptor (fs_nofollow).
        patch("boxmunge.fs_nofollow.os.fchown"),
        patch("boxmunge.fs_nofollow.os.getuid", return_value=1000),
    )


class TestModes:
    def test_modes_survive_a_round_trip(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        paths.config_file.write_text("hostname: t\nadmin_email: t@t\n")
        paths.backup_key.write_text("AGE-SECRET-KEY-1X\n")
        paths.backup_key.chmod(0o640)
        _setup_project(paths, "myapp")
        smoke = paths.project_dir("myapp") / "boxmunge-scripts" / "smoke.sh"
        smoke.parent.mkdir()
        smoke.write_text("#!/bin/sh\nexit 0\n")
        smoke.chmod(0o755)
        paths.project_compose("myapp").chmod(0o644)
        archive = create_stash(paths)

        for f in (paths.backup_key, smoke, paths.project_compose("myapp")):
            f.write_text("changed\n")
            f.chmod(0o600)
        restore_stash(paths, archive)

        assert paths.backup_key.stat().st_mode & 0o7777 == 0o640
        assert smoke.stat().st_mode & 0o7777 == 0o755
        assert paths.project_compose("myapp").stat().st_mode & 0o7777 == 0o644
        assert smoke.read_text() == "#!/bin/sh\nexit 0\n"

    def test_special_mode_bits_are_dropped(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        info = tarfile.TarInfo(name="projects/myapp/compose.yml")
        info.mode = 0o4755
        archive = paths.stashes / "boxmunge-stash-2026-01-01T000000.tar.gz"
        _build_malicious_archive(archive, [(info, b"services: {}\n")])
        restore_stash(paths, archive)
        assert paths.project_compose("myapp").stat().st_mode & 0o7777 == 0o755


class TestOwners:
    def test_owner_restored_when_root(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        info = tarfile.TarInfo(name="config/backup.key")
        info.uid, info.gid, info.mode = 0, 1000, 0o640
        archive = paths.stashes / "boxmunge-stash-2026-01-01T000000.tar.gz"
        _build_malicious_archive(archive, [(info, b"AGE-SECRET-KEY-1X\n")])
        euid, pw, chown, getuid = _as_root(1000, 1000)
        with euid, pw, chown as mock_chown, getuid:
            restore_stash(paths, archive)
        assert [c.args[1:] for c in mock_chown.call_args_list] == [(0, 1000)]

    def test_unexpected_owner_is_refused_when_root(self, tmp_path: Path) -> None:
        paths = _make_paths(tmp_path)
        info = tarfile.TarInfo(name="config/boxmunge.yml")
        info.uid, info.gid = 4242, 4242
        archive = paths.stashes / "boxmunge-stash-2026-01-01T000000.tar.gz"
        _build_malicious_archive(archive, [(info, b"hostname: x\n")])
        euid, pw, chown, getuid = _as_root(1000, 1000)
        with euid, pw, chown, getuid:
            with pytest.raises(StashError, match="owner"):
                restore_stash(paths, archive)
        assert not paths.config_file.exists()


class TestLifecycleMarkers:
    def _paths(self, tmp_path: Path) -> BoxPaths:
        paths = _make_paths(tmp_path)
        _setup_project(paths, "myapp")
        return paths

    def test_cleared_markers_stay_cleared(self, tmp_path: Path) -> None:
        paths = self._paths(tmp_path)
        paths.project_paused_state("myapp").write_text("{}")
        paths.project_quarantine_state("myapp").write_text("{}")
        archive = create_stash(paths)
        paths.project_paused_state("myapp").unlink()
        paths.project_quarantine_state("myapp").unlink()
        paths.project_deploy_state("myapp").write_text("{}")

        restore_stash(paths, archive)

        assert not paths.project_paused_state("myapp").exists()
        assert not paths.project_quarantine_state("myapp").exists()
        assert "abc123" in paths.project_deploy_state("myapp").read_text()

    def test_new_markers_survive(self, tmp_path: Path) -> None:
        paths = self._paths(tmp_path)
        archive = create_stash(paths)
        paths.project_paused_state("myapp").write_text('{"reason": "now"}')
        restore_stash(paths, archive)
        assert paths.project_paused_state("myapp").read_text() == '{"reason": "now"}'
