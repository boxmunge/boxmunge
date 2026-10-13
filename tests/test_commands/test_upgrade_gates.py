# SPDX-License-Identifier: Apache-2.0
"""D-07: a failed upgrade gate fails the upgrade (non-zero, version not
recorded), so the shim rolls back instead of printing "Upgrade complete"."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_steps import UpgradeGateError, regenerate_configs
from boxmunge.docker import DockerError
from boxmunge.version import read_installed_version
from tests.test_commands.test_upgrade_dry_run_and_pause import _pause, _project, _setup

OLD = "0.2.0+abc1234"


@pytest.fixture
def paths(tmp_path: Path):
    paths = _setup(tmp_path)
    _project(paths, "alpha")
    return paths


def test_regen_failure_raises(paths) -> None:
    with patch("boxmunge.commands.upgrade_steps.prepare_compose_override",
               side_effect=RuntimeError("generator bug")):
        with pytest.raises(UpgradeGateError, match="alpha"):
            regenerate_configs(paths)


def test_maintenance_render_failure_raises(paths) -> None:
    _pause(paths, "alpha")
    with patch("boxmunge.commands.upgrade_steps.atomic_write_text",
               side_effect=OSError("disk full")):
        with pytest.raises(UpgradeGateError, match="maintenance"):
            regenerate_configs(paths)


@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_apply_regen_failure_fails_without_restarting(mock_up, _reload, paths, capsys) -> None:
    with patch("boxmunge.commands.upgrade_steps.prepare_compose_override",
               side_effect=RuntimeError("generator bug")):
        assert run_upgrade(paths, apply_only=True) == 1
    mock_up.assert_not_called()
    assert read_installed_version(paths) == OLD
    assert "ERROR: upgrade failed" in capsys.readouterr().err


@patch("boxmunge.commands.upgrade_cmd.caddy_reload", side_effect=DockerError("caddy down"))
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_apply_caddy_reload_failure_fails(mock_up, _reload, paths) -> None:
    assert run_upgrade(paths, apply_only=True) == 1
    mock_up.assert_not_called()
    assert read_installed_version(paths) == OLD


@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.commands.upgrade_steps.compose_up", side_effect=DockerError("boom"))
def test_apply_restart_failure_does_not_record_version(_up, _reload, paths) -> None:
    assert run_upgrade(paths, apply_only=True) == 1
    assert read_installed_version(paths) == OLD


@patch("boxmunge.commands.upgrade_cmd.run_health", return_value=0)
@patch("boxmunge.commands.upgrade_cmd.run_self_test", return_value=1)
@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_full_self_test_failure_fails(_up, _reload, _self_test, _health, paths, capsys) -> None:
    assert run_upgrade(paths) == 1
    assert read_installed_version(paths) == OLD
    assert "Upgrade complete" not in capsys.readouterr().out


@patch("boxmunge.commands.upgrade_cmd.get_build_version", return_value="0.3.0")
@patch("boxmunge.commands.upgrade_cmd.run_health", return_value=0)
@patch("boxmunge.commands.upgrade_cmd.run_self_test", return_value=0)
@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_full_success_records_version(_up, _reload, _st, _health, _ver, paths, capsys) -> None:
    assert run_upgrade(paths) == 0
    assert read_installed_version(paths) == "0.3.0"
    assert "Upgrade complete" in capsys.readouterr().out
