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
)

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
