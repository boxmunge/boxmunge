"""Tests for boxmunge.backup — encryption, decryption, and pruning."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge.backup import (
    encrypt_file,
    decrypt_file,
    prune_backups,
    backup_filename,
    resolve_backup_service,
    BackupError,
)


class TestResolveBackupService:
    """backup.service resolution — single source of truth shared by
    backup and restore. The old default of 'web' silently targeted a
    non-existent container for every project not named 'web'."""

    def test_explicit_service_wins(self) -> None:
        manifest = {
            "services": {"web": {}, "db": {}},
            "backup": {"service": "db"},
        }
        assert resolve_backup_service(manifest) == "db"

    def test_single_service_inferred(self) -> None:
        manifest = {"services": {"wwgs": {}}, "backup": {"type": "custom"}}
        assert resolve_backup_service(manifest) == "wwgs"

    def test_explicit_service_may_be_backend_absent_from_services(self) -> None:
        """A db backend often lives only in compose.yml, not the manifest
        services block (canary does exactly this). Resolution must not
        cross-check against services."""
        manifest = {
            "services": {"web": {}},
            "backup": {"service": "db"},
        }
        assert resolve_backup_service(manifest) == "db"

    def test_ambiguous_multi_service_raises(self) -> None:
        manifest = {
            "services": {"web": {}, "worker": {}},
            "backup": {"type": "custom"},
        }
        with pytest.raises(BackupError, match="backup.service is not set"):
            resolve_backup_service(manifest)

# Dummy age identity file content for tests
AGE_IDENTITY = (
    "# created: 2026-01-01T00:00:00Z\n"
    "# public key: age1test000000000000000000000000000000000000000000000000000qkzsl7\n"
    "AGE-SECRET-KEY-1TEST000000000000000000000000000000000000000000000000000000\n"
)


class TestBackupFilename:
    def test_generates_timestamped_name(self) -> None:
        name = backup_filename("myapp")
        assert name.startswith("myapp-")
        assert name.endswith(".tar.gz.age")
        assert "T" in name

    def test_different_projects_different_names(self) -> None:
        a = backup_filename("alpha")
        b = backup_filename("beta")
        assert a.startswith("alpha-")
        assert b.startswith("beta-")


class TestEncryptFile:
    def test_encrypt_runs_age_in_the_container(self, paths, system_container) -> None:
        paths.backup_key.write_text(AGE_IDENTITY)
        bdir = paths.project_backups("myapp")
        bdir.mkdir(parents=True)
        input_file = bdir / ".dump-x.tar.gz"
        input_file.write_bytes(b"fake archive data here")
        output_file = bdir / "myapp-2026.tar.gz.age"

        encrypt_file(input_file, output_file, paths)

        [cmd] = system_container.calls
        assert cmd[:2] == ["age", "--encrypt"]
        assert cmd[cmd.index("-o") + 1].startswith("/projects/myapp/backups/.encrypt-")
        assert cmd[-1] == "/projects/myapp/backups/.dump-x.tar.gz"
        assert output_file.exists()
        assert [f.name for f in bdir.iterdir() if f.name.startswith(".encrypt-")] == []

    def test_encrypt_raises_on_missing_key(self, paths) -> None:
        input_file = paths.projects / "data.tar.gz"
        input_file.write_bytes(b"data")
        with pytest.raises(FileNotFoundError, match="key"):
            encrypt_file(input_file, paths.projects / "out.age", paths)


class TestNoHostFallback:
    """D-08/C-20: when the system container is missing, age must not run on
    the host. The old code silently ran host age, which is how the v0.9.16
    /tmp decrypt bug passed every test."""

    @pytest.fixture
    def no_container(self, paths, monkeypatch):
        import boxmunge.system_container as sc
        monkeypatch.setattr(sc, "_inspect", lambda name: None)
        paths.backup_key.write_text(AGE_IDENTITY)
        bdir = paths.project_backups("myapp")
        bdir.mkdir(parents=True)
        return bdir

    def test_encrypt_fails_loudly_and_leaves_no_temp(self, paths, no_container) -> None:
        dump = no_container / ".dump-x.tar.gz"
        dump.write_bytes(b"x")
        with patch("subprocess.run") as host_run:
            with pytest.raises(BackupError, match="does not exist.*up -d --build"):
                encrypt_file(dump, no_container / "out.tar.gz.age", paths)
        host_run.assert_not_called()
        assert sorted(f.name for f in no_container.iterdir()) == [".dump-x.tar.gz"]

    def test_decrypt_fails_loudly(self, paths, no_container) -> None:
        snap = no_container / "myapp-1.tar.gz.age"
        snap.write_bytes(b"x")
        with patch("subprocess.run") as host_run:
            with pytest.raises(BackupError, match="never fall back to host tools"):
                decrypt_file(snap, no_container / "out", paths)
        host_run.assert_not_called()


class TestMatchDirOwnership:
    """Backup temp files (mkstemp, mode 0600, owned by the invoking user) must
    be readable by the system container's age process (a fixed uid). When a
    backup is invoked as root (e.g. the container-update pre-deploy backup),
    the temp is root-owned and age (uid 1000) gets 'permission denied'. The
    helper aligns the temp's ownership with its backups dir so age can access
    it regardless of the invoking user, without changing the 0600 mode.
    """

    def _stat_with(self, uid: int, gid: int):
        m = MagicMock()
        m.st_uid, m.st_gid = uid, gid
        return m

    def test_chowns_temp_to_dir_owner_when_mismatched(
        self, tmp_path: Path
    ) -> None:
        from boxmunge import backup
        f = tmp_path / ".dump-x.tar.gz"
        f.write_text("x")

        def fake_stat(p):
            # backups dir owned 1000:1000; the root-invoked temp is 0:0
            return self._stat_with(1000, 1000) if str(p) == str(tmp_path) \
                else self._stat_with(0, 0)

        chown_calls = []
        with patch("boxmunge.backup.os.stat", side_effect=fake_stat), \
             patch("boxmunge.backup.os.chown",
                   side_effect=lambda p, u, g: chown_calls.append((str(p), u, g))):
            backup._match_dir_ownership(f)
        assert chown_calls == [(str(f), 1000, 1000)]

    def test_no_chown_when_ownership_already_aligned(
        self, tmp_path: Path
    ) -> None:
        from boxmunge import backup
        f = tmp_path / ".dump-y.tar.gz"
        f.write_text("y")

        chown_calls = []
        with patch("boxmunge.backup.os.stat",
                   side_effect=lambda p: self._stat_with(1000, 1000)), \
             patch("boxmunge.backup.os.chown",
                   side_effect=lambda *a: chown_calls.append(a)):
            backup._match_dir_ownership(f)
        assert chown_calls == []  # daily (deploy/1000) path: already aligned


class TestDecryptFile:
    def test_decrypt_runs_age_in_the_container(self, paths, system_container) -> None:
        bdir = paths.project_backups("myapp")
        bdir.mkdir(parents=True)
        input_file = bdir / "myapp-1.tar.gz.age"
        input_file.write_bytes(b"encrypted data")

        decrypt_file(input_file, bdir / "out.tar.gz", paths)

        [cmd] = system_container.calls
        assert cmd[:2] == ["age", "--decrypt"]
        assert cmd[cmd.index("-i") + 1] == "/config/backup.key"
        assert cmd[cmd.index("-o") + 1] == "/projects/myapp/backups/out.tar.gz"
        assert (bdir / "out.tar.gz").read_bytes() == b"plaintext snapshot"

    def test_decrypt_to_unmounted_path_fails_before_age_runs(
        self, paths, system_container, tmp_path,
    ) -> None:
        """The v0.9.16 shape: a decrypt target outside the mounts."""
        bdir = paths.project_backups("myapp")
        bdir.mkdir(parents=True)
        (bdir / "myapp-1.tar.gz.age").write_bytes(b"x")
        with pytest.raises(BackupError, match="outside the system container's mounts"):
            decrypt_file(bdir / "myapp-1.tar.gz.age", tmp_path / "out", paths)
        assert system_container.calls == []


class TestPruneBackups:
    def test_prunes_oldest_beyond_retention(self, tmp_path: Path) -> None:
        for i in range(5):
            f = tmp_path / f"myapp-2026-03-{20+i:02d}T020000.tar.gz.age"
            f.write_bytes(b"data")
            os.utime(f, (1000000 + i * 86400, 1000000 + i * 86400))

        pruned = prune_backups(tmp_path, "myapp", retention=3)
        remaining = sorted(tmp_path.glob("myapp-*.tar.gz.age"))
        assert len(remaining) == 3
        assert len(pruned) == 2

    def test_noop_when_under_retention(self, tmp_path: Path) -> None:
        for i in range(2):
            f = tmp_path / f"myapp-2026-03-{20+i:02d}T020000.tar.gz.age"
            f.write_bytes(b"data")

        pruned = prune_backups(tmp_path, "myapp", retention=5)
        assert len(pruned) == 0
        assert len(list(tmp_path.glob("myapp-*.tar.gz.age"))) == 2

    def test_only_prunes_matching_project(self, tmp_path: Path) -> None:
        (tmp_path / "myapp-2026-03-20T020000.tar.gz.age").write_bytes(b"data")
        (tmp_path / "other-2026-03-20T020000.tar.gz.age").write_bytes(b"data")

        prune_backups(tmp_path, "myapp", retention=0)
        assert (tmp_path / "other-2026-03-20T020000.tar.gz.age").exists()
