# SPDX-License-Identifier: Apache-2.0
"""Tests for upgrade_cmd --dry-run and --apply flags."""

from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version
from boxmunge.commands.upgrade_cmd import run_upgrade


def _setup_paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.2.0", "abc1234")
    return paths


class TestDryRun:
    def test_dry_run_returns_zero_with_no_projects(self, tmp_path):
        paths = _setup_paths(tmp_path)
        result = run_upgrade(paths, dry_run=True)
        assert result == 0

    def test_dry_run_does_not_write_version_file(self, tmp_path):
        paths = _setup_paths(tmp_path)
        original = paths.version_file.read_text()
        run_upgrade(paths, dry_run=True)
        assert paths.version_file.read_text() == original

    def test_dry_run_does_not_create_stash(self, tmp_path):
        paths = _setup_paths(tmp_path)
        run_upgrade(paths, dry_run=True)
        stashes = list(paths.stashes.glob("*.tar.gz"))
        assert len(stashes) == 0

    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    def test_dry_run_does_not_reload_caddy(self, mock_reload, tmp_path):
        paths = _setup_paths(tmp_path)
        run_upgrade(paths, dry_run=True)
        mock_reload.assert_not_called()

    @patch("boxmunge.commands.upgrade_cmd.compose_up")
    def test_dry_run_does_not_restart_projects(self, mock_up, tmp_path):
        paths = _setup_paths(tmp_path)
        run_upgrade(paths, dry_run=True)
        mock_up.assert_not_called()


class TestApplyMode:
    @patch("boxmunge.commands.upgrade_cmd.caddy_reload")
    def test_apply_skips_stash(self, mock_reload, tmp_path):
        paths = _setup_paths(tmp_path)
        result = run_upgrade(paths, apply_only=True)
        assert result == 0
        stashes = list(paths.stashes.glob("*.tar.gz"))
        assert len(stashes) == 0
