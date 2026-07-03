"""Tests for boxmunge.backup — encryption, decryption, and pruning."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

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
    def test_encrypt_creates_output(self, tmp_path: Path) -> None:
        key_file = tmp_path / "backup.key"
        key_file.write_text(AGE_IDENTITY)
        input_file = tmp_path / "data.tar.gz"
        input_file.write_bytes(b"fake archive data here")
        output_file = tmp_path / "data.tar.gz.age"

        with patch("boxmunge.backup._run_age_cmd") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0)
            encrypt_file(input_file, output_file, key_file)
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "age" in cmd[0]

    def test_encrypt_raises_on_missing_key(self, tmp_path: Path) -> None:
        input_file = tmp_path / "data.tar.gz"
        input_file.write_bytes(b"data")
        with pytest.raises(FileNotFoundError, match="key"):
            encrypt_file(input_file, tmp_path / "out.age", tmp_path / "nokey")


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
    def test_decrypt_calls_age(self, tmp_path: Path) -> None:
        key_file = tmp_path / "backup.key"
        key_file.write_text(AGE_IDENTITY)
        input_file = tmp_path / "data.tar.gz.age"
        input_file.write_bytes(b"encrypted data")
        output_file = tmp_path / "data.tar.gz"

        with patch("boxmunge.backup._run_age_cmd") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0)
            decrypt_file(input_file, output_file, key_file)
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "age" in cmd[0]
            assert "--decrypt" in cmd


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
