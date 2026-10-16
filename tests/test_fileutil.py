"""Tests for boxmunge.fileutil — atomic writes and project locking."""

import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.fileutil import atomic_write_bytes, atomic_write_text
from boxmunge.fileutil import open_shared_lockfile, project_lock, LockError
from boxmunge.fileutil import mkdir_p_deploy
from boxmunge.paths import BoxPaths


class TestOpenSharedLockfile:
    def test_creates_parent_dir(self, tmp_path: Path) -> None:
        lock = tmp_path / "deep" / "nested" / ".test.lock"
        fd = open_shared_lockfile(lock)
        try:
            assert lock.exists()
            assert lock.parent.is_dir()
        finally:
            os.close(fd)

    def test_file_mode_is_group_writable(self, tmp_path: Path) -> None:
        """Mode 0o660 so root and deploy group can both take the flock.

        Regression: when root creates the lock first (e.g. upgrade shim),
        deploy was getting EACCES on subsequent flock attempts.
        """
        lock = tmp_path / ".group-writable.lock"
        fd = open_shared_lockfile(lock)
        try:
            mode = lock.stat().st_mode & 0o777
            assert mode & 0o060 == 0o060, f"mode {oct(mode)} is not group-writable"
            assert mode & 0o007 == 0, f"mode {oct(mode)} lets other users take the lock"
        finally:
            os.close(fd)

    def test_existing_file_chmodded_to_0o660(self, tmp_path: Path) -> None:
        """If a file exists at narrower perms (e.g. created by older code),
        the helper must widen it on next open so locks remain shareable."""
        lock = tmp_path / ".old.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o644)  # world-readable, as earlier versions left them
        fd = open_shared_lockfile(lock)
        try:
            mode = lock.stat().st_mode & 0o777
            assert mode == 0o660, f"mode should have been set to 0o660, got {oct(mode)}"
        finally:
            os.close(fd)

    def test_returns_writable_fd(self, tmp_path: Path) -> None:
        lock = tmp_path / ".writable.lock"
        fd = open_shared_lockfile(lock)
        try:
            os.write(fd, b"x")  # would EBADF if read-only
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, 1) == b"x"
        finally:
            os.close(fd)


class TestMkdirPDeploy:
    """The mkdir -p variant that chowns each newly-created dir to deploy.

    Regression: a root-run code path created `<project>/security/` while
    the file inside was atomically chowned to deploy; later
    `security suppress` from the unprivileged deploy shell hit EACCES
    trying to mkstemp under the root-owned dir.
    """

    def test_creates_full_chain(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "c"
        mkdir_p_deploy(target)
        assert target.is_dir()
        assert (tmp_path / "a").is_dir()
        assert (tmp_path / "a" / "b").is_dir()

    def test_chowns_only_newly_created_dirs(self, tmp_path: Path) -> None:
        # tmp_path/a exists already; tmp_path/a/b and tmp_path/a/b/c are new.
        existing = tmp_path / "a"
        existing.mkdir()
        chowned: list[str] = []
        with patch(
            "boxmunge.fileutil._chown_deploy",
            side_effect=lambda p: chowned.append(p),
        ):
            mkdir_p_deploy(existing / "b" / "c")
        assert str(existing) not in chowned, (
            "pre-existing dir must not be chowned"
        )
        assert str(existing / "b") in chowned
        assert str(existing / "b" / "c") in chowned

    def test_existing_target_is_noop(self, tmp_path: Path) -> None:
        target = tmp_path / "already-here"
        target.mkdir()
        chowned: list[str] = []
        with patch(
            "boxmunge.fileutil._chown_deploy",
            side_effect=lambda p: chowned.append(p),
        ):
            mkdir_p_deploy(target)
        assert chowned == [], "nothing was created, nothing to chown"

    def test_race_loser_does_not_chown(self, tmp_path: Path) -> None:
        """If another process creates the dir between our exists() check
        and mkdir(), we must not chown — ownership belongs to the winner."""
        target = tmp_path / "race"
        chowned: list[str] = []
        real_mkdir = Path.mkdir

        def racing_mkdir(self, *args, **kwargs):
            # Simulate another process winning: create the dir, then let
            # our mkdir raise FileExistsError as it would in production.
            if str(self) == str(target):
                real_mkdir(self, *args, **kwargs)
                raise FileExistsError
            return real_mkdir(self, *args, **kwargs)

        with patch.object(Path, "mkdir", racing_mkdir), patch(
            "boxmunge.fileutil._chown_deploy",
            side_effect=lambda p: chowned.append(p),
        ):
            mkdir_p_deploy(target)
        assert target.is_dir()
        assert chowned == []


class TestAtomicWriteText:
    def test_writes_content(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        atomic_write_text(target, "hello world")
        assert target.read_text() == "hello world"

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        target.write_text("old content")
        atomic_write_text(target, "new content")
        assert target.read_text() == "new content"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "dir" / "test.txt"
        atomic_write_text(target, "nested")
        assert target.read_text() == "nested"

    def test_no_temp_file_on_success(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        atomic_write_text(target, "content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_no_partial_write_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        target.write_text("original")
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_text(target, "new content that should not appear")
        assert target.read_text() == "original"

    def test_temp_cleaned_up_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.txt"
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_text(target, "content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []


class TestAtomicWriteBytes:
    def test_writes_content(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        atomic_write_bytes(target, b"hello world")
        assert target.read_bytes() == b"hello world"

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        target.write_bytes(b"old content")
        atomic_write_bytes(target, b"new content")
        assert target.read_bytes() == b"new content"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "dir" / "test.bin"
        atomic_write_bytes(target, b"nested")
        assert target.read_bytes() == b"nested"

    def test_no_temp_file_on_success(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        atomic_write_bytes(target, b"content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_no_partial_write_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        target.write_bytes(b"original")
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_bytes(target, b"new content that should not appear")
        assert target.read_bytes() == b"original"

    def test_temp_cleaned_up_on_error(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        with patch("boxmunge.fileutil.os.fsync", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                atomic_write_bytes(target, b"content")
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_rename_failure_keeps_original(self, tmp_path: Path) -> None:
        """SIGKILL-equivalent: rename fails mid-write, original intact."""
        target = tmp_path / "test.bin"
        target.write_bytes(b"original")
        with patch("boxmunge.fileutil.os.rename", side_effect=OSError("simulated")):
            with pytest.raises(OSError):
                atomic_write_bytes(target, b"would-be-new")
        assert target.read_bytes() == b"original"
        temps = list(tmp_path.glob(".*tmp"))
        assert temps == []

    def test_mode_applied(self, tmp_path: Path) -> None:
        target = tmp_path / "test.bin"
        atomic_write_bytes(target, b"content", mode=0o600)
        assert (target.stat().st_mode & 0o777) == 0o600


class TestProjectLock:
    def test_acquires_and_releases(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            lock_file = paths.project_lock_file("myapp")
            assert lock_file.exists()

    def test_blocks_concurrent_lock(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            with pytest.raises(LockError, match="Another operation"):
                with project_lock("myapp", paths):
                    pass

    def test_different_projects_independent(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("app-a", paths):
            with project_lock("app-b", paths):
                pass  # should not raise

    def test_lock_file_persists_after_release(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            pass
        assert paths.project_lock_file("myapp").exists()

    def test_reacquire_after_release(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        paths.state.mkdir(parents=True, exist_ok=True)
        with project_lock("myapp", paths):
            pass
        with project_lock("myapp", paths):
            pass  # should not raise


class TestChownDeployErrorClass:
    """Audit I-NEW-1 / C-NEW-4: KeyError silent, OSError logs warning.

    The boxmunge logger sets propagate=False once it has been initialised
    by an earlier test, so caplog (which intercepts via the root logger)
    can't see records. These tests attach a temporary handler directly to
    the boxmunge logger to capture records reliably.
    """

    @staticmethod
    def _captured_records() -> tuple[logging.Handler, list]:
        import logging as _l
        records: list = []

        class _ListHandler(_l.Handler):
            def emit(self, record):  # type: ignore[override]
                records.append(record)

        h = _ListHandler(level=_l.WARNING)
        return h, records

    def test_no_deploy_user_silent(self, tmp_path: Path) -> None:
        import logging as _l
        from boxmunge.fileutil import _chown_deploy
        target = tmp_path / "f"
        target.write_text("x")
        h, records = self._captured_records()
        _l.getLogger("boxmunge").addHandler(h)
        try:
            with patch("boxmunge.fileutil.os.getuid", return_value=0), \
                 patch("boxmunge.fileutil.pwd.getpwnam",
                       side_effect=KeyError("deploy")):
                _chown_deploy(str(target))
        finally:
            _l.getLogger("boxmunge").removeHandler(h)
        assert records == []

    def test_oserror_logs_warning(self, tmp_path: Path) -> None:
        import logging as _l
        from boxmunge.fileutil import _chown_deploy
        target = tmp_path / "f"
        target.write_text("x")

        class _PW:
            pw_uid = 1000
            pw_gid = 1000

        h, records = self._captured_records()
        _l.getLogger("boxmunge").addHandler(h)
        try:
            with patch("boxmunge.fileutil.os.getuid", return_value=0), \
                 patch("boxmunge.fileutil.pwd.getpwnam", return_value=_PW), \
                 patch("boxmunge.fileutil.os.chown",
                       side_effect=OSError("EPERM")):
                _chown_deploy(str(target))
        finally:
            _l.getLogger("boxmunge").removeHandler(h)
        # OSError must surface in the boxmunge logger (forensic trail).
        assert len(records) == 1
        msg = records[0].getMessage()
        assert "chown" in msg.lower()
        assert "EPERM" in msg

    def test_non_root_silent_no_log(self, tmp_path: Path) -> None:
        import logging as _l
        from boxmunge.fileutil import _chown_deploy
        target = tmp_path / "f"
        target.write_text("x")
        h, records = self._captured_records()
        _l.getLogger("boxmunge").addHandler(h)
        try:
            with patch("boxmunge.fileutil.os.getuid", return_value=1000):
                _chown_deploy(str(target))
        finally:
            _l.getLogger("boxmunge").removeHandler(h)
        assert records == []


class TestDurability:
    """A rename is atomic but not durable until its directory is synced: after
    a power cut the old file, or an empty new one, could come back."""

    def _record(self, events: list[str]):
        import stat
        real_fsync, real_rename = os.fsync, os.rename

        def fsync(fd: int) -> None:
            kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
            events.append(f"fsync-{kind}")
            real_fsync(fd)

        def rename(src, dst) -> None:
            events.append("rename")
            real_rename(src, dst)

        return (patch("boxmunge.fileutil.os.fsync", fsync),
                patch("boxmunge.fileutil.os.rename", rename))

    @pytest.mark.parametrize("write", [
        lambda p: atomic_write_text(p, "new"),
        lambda p: atomic_write_bytes(p, b"new"),
    ])
    def test_syncs_file_then_renames_then_syncs_directory(self, tmp_path: Path, write) -> None:
        target = tmp_path / "state.json"
        target.write_text("old")
        events: list[str] = []
        fsync_patch, rename_patch = self._record(events)
        with fsync_patch, rename_patch:
            write(target)
        assert events == ["fsync-file", "rename", "fsync-dir"]
        assert target.read_text() == "new"

    def test_durable_rename_syncs_a_file_written_elsewhere(self, tmp_path: Path) -> None:
        """The backup writer's temp is written by age in another container."""
        from boxmunge.fileutil import durable_rename
        tmp, target = tmp_path / ".enc.tmp", tmp_path / "backup.age"
        tmp.write_bytes(b"ciphertext")
        events: list[str] = []
        fsync_patch, rename_patch = self._record(events)
        with fsync_patch, rename_patch:
            durable_rename(tmp, target)
        assert events == ["fsync-file", "rename", "fsync-dir"]
        assert target.read_bytes() == b"ciphertext" and not tmp.exists()

    def test_mode_and_owner_are_set_before_the_file_is_visible(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.yml"
        seen: list[tuple[str, int]] = []
        real_rename = os.rename

        def rename(src, dst) -> None:
            seen.append(("rename", os.stat(src).st_mode & 0o777))
            real_rename(src, dst)

        with patch("boxmunge.fileutil.os.rename", rename), \
             patch("boxmunge.fileutil._fchown_deploy",
                   side_effect=lambda fd, what: seen.append(("chown", 0))):
            atomic_write_text(target, "k: v", mode=0o600)
        assert seen == [("chown", 0), ("rename", 0o600)]


class TestOpenRegularNofollow:
    """Root opening names in deploy-writable dirs must not be redirected."""

    @pytest.mark.parametrize("make", ["symlink", "hardlink", "fifo", "dir"])
    def test_refuses_anything_but_a_plain_file(self, tmp_path: Path, make: str) -> None:
        from boxmunge.fileutil import open_regular_nofollow
        victim = tmp_path / "victim"
        victim.write_text("keep")
        name = tmp_path / "name"
        {"symlink": lambda: name.symlink_to(victim),
         "hardlink": lambda: os.link(victim, name),
         "fifo": lambda: os.mkfifo(name),
         "dir": lambda: name.mkdir()}[make]()
        with pytest.raises(OSError):
            os.close(open_regular_nofollow(name, os.O_RDONLY | os.O_NONBLOCK))
        assert victim.read_text() == "keep"

    def test_lock_file_planted_as_symlink_is_refused(self, tmp_path: Path) -> None:
        victim = tmp_path / "victim"
        victim.write_text("keep")
        victim.chmod(0o600)
        lock = tmp_path / ".x.lock"
        lock.symlink_to(victim)
        with pytest.raises(OSError):
            open_shared_lockfile(lock)
        assert victim.stat().st_mode & 0o777 == 0o600

    def test_chmod_nofollow_refuses_a_symlink(self, tmp_path: Path) -> None:
        from boxmunge.fileutil import chmod_nofollow
        victim = tmp_path / "victim"
        victim.write_text("x")
        victim.chmod(0o600)
        link = tmp_path / "link.sh"
        link.symlink_to(victim)
        with pytest.raises(OSError):
            chmod_nofollow(link, add=0o755)
        assert victim.stat().st_mode & 0o777 == 0o600

    @pytest.mark.parametrize("start", [0o000, 0o200])
    def test_chmod_nofollow_works_on_an_unreadable_file_of_ones_own(
            self, tmp_path: Path, start: int) -> None:
        from boxmunge.fileutil import chmod_nofollow
        script = tmp_path / "smoke.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(start)
        chmod_nofollow(script, add=0o755)
        assert script.stat().st_mode & 0o777 == start | 0o755
