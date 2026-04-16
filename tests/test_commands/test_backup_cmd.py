"""Tests for boxmunge backup command logic."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge.commands.backup_cmd import run_backup, list_snapshots
from boxmunge.paths import BoxPaths


MANIFEST_WITH_BACKUP = """\
project: myapp
repo: ""
ref: main
hosts:
  - myapp.example.com
services:
  web:
    type: frontend
    port: 3000
    routes:
      - path: /
backup:
  type: db-dump
  dump_command: "boxmunge-scripts/backup.sh"
  restore_command: "boxmunge-scripts/restore.sh"
  retention: 3
env_files: []
"""

MANIFEST_NO_BACKUP = """\
project: myapp
repo: ""
ref: main
hosts:
  - myapp.example.com
services:
  web:
    type: frontend
    port: 3000
    routes:
      - path: /
backup:
  type: none
env_files: []
"""


def _setup_project(paths: BoxPaths, manifest: str) -> None:
    pdir = paths.project_dir("myapp")
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(manifest)
    (pdir / "backups").mkdir()
    scripts = pdir / "boxmunge-scripts"
    scripts.mkdir()
    (scripts / "backup.sh").write_text("#!/bin/bash\necho 'dump data'")
    (scripts / "backup.sh").chmod(0o755)
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("dGVzdC1rZXktZm9yLWJhY2t1cHM=\n")


class TestRunBackup:
    @patch("boxmunge.commands.backup_cmd._execute_dump")
    @patch("boxmunge.backup.encrypt_file")
    def test_backup_succeeds_with_dump_type(
        self, mock_encrypt: MagicMock, mock_dump: MagicMock, paths: BoxPaths
    ) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        mock_dump.return_value = paths.project_dir("myapp") / "backups" / "raw.tar.gz"
        mock_dump.return_value.write_bytes(b"fake")

        exit_code = run_backup("myapp", paths)
        assert exit_code == 0
        mock_dump.assert_called_once()
        mock_encrypt.assert_called_once()

    def test_backup_skipped_for_none_type(self, paths: BoxPaths) -> None:
        _setup_project(paths, MANIFEST_NO_BACKUP)
        exit_code = run_backup("myapp", paths)
        assert exit_code == 0

    def test_backup_fails_missing_project(self, paths: BoxPaths) -> None:
        exit_code = run_backup("nope", paths)
        assert exit_code == 1

    def test_backup_fails_pre_registered(self, paths: BoxPaths, capsys) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")

        exit_code = run_backup("myapp", paths)
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "pre-registered" in captured.out
        assert "boxmunge deploy myapp" in captured.out


class TestListSnapshots:
    def test_lists_existing_snapshots(self, paths: BoxPaths) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        bdir = paths.project_backups("myapp")
        (bdir / "myapp-2026-03-28T020000.tar.gz.age").write_bytes(b"a")
        (bdir / "myapp-2026-03-29T020000.tar.gz.age").write_bytes(b"b")

        snaps = list_snapshots(paths, "myapp")
        assert len(snaps) == 2

    def test_empty_when_no_backups(self, paths: BoxPaths) -> None:
        _setup_project(paths, MANIFEST_WITH_BACKUP)
        snaps = list_snapshots(paths, "myapp")
        assert snaps == []
