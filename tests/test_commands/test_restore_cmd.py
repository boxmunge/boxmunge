"""Tests for boxmunge restore command logic."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from boxmunge.commands.restore import run_restore
from boxmunge.paths import BoxPaths


MANIFEST = """\
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


def _setup_project(paths: BoxPaths) -> None:
    pdir = paths.project_dir("myapp")
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(MANIFEST)
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    bdir = pdir / "backups"
    bdir.mkdir()
    (bdir / "myapp-2026-03-29T020000.tar.gz.age").write_bytes(b"encrypted")
    scripts = pdir / "boxmunge-scripts"
    scripts.mkdir()
    (scripts / "restore.sh").write_text("#!/bin/bash\ncat > /dev/null")
    (scripts / "restore.sh").chmod(0o755)
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("dGVzdC1rZXk=\n")


class TestRunRestore:
    def test_fails_missing_project(self, paths: BoxPaths) -> None:
        exit_code = run_restore("nope", paths, snapshot=None, yes=True)
        assert exit_code == 1

    def test_fails_no_snapshots(self, paths: BoxPaths) -> None:
        _setup_project(paths)
        for f in paths.project_backups("myapp").glob("*.age"):
            f.unlink()
        exit_code = run_restore("myapp", paths, snapshot=None, yes=True)
        assert exit_code == 1

    @patch("boxmunge.commands.restore._restore_snapshot")
    @patch("boxmunge.commands.restore.compose_down")
    @patch("boxmunge.commands.restore.compose_up")
    def test_restore_with_named_snapshot(
        self, mock_up: MagicMock, mock_down: MagicMock,
        mock_restore: MagicMock, paths: BoxPaths
    ) -> None:
        _setup_project(paths)
        mock_restore.return_value = True
        exit_code = run_restore(
            "myapp", paths,
            snapshot="myapp-2026-03-29T020000.tar.gz.age",
            yes=True,
        )
        assert exit_code == 0
        mock_down.assert_called_once()
        mock_restore.assert_called_once()
        mock_up.assert_called_once()
