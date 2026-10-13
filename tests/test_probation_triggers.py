# SPDX-License-Identifier: Apache-2.0
"""C-07: only an operator's backup ends upgrade probation. The nightly
backup-all timer, container-update's pre-update backup and self-test call the
same run_backup and must leave probation (and container-update's probation
gate) in place."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.backup_cmd import cmd_backup, run_backup, run_backup_all
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_state import read_probation, write_probation
from tests.test_commands.test_backup_cmd import MANIFEST_NO_BACKUP, _setup_project


@pytest.fixture
def on_probation(paths: BoxPaths) -> BoxPaths:
    paths.upgrade_state.mkdir(parents=True, exist_ok=True)
    write_probation(paths, "1.2.3", "b")
    _setup_project(paths, MANIFEST_NO_BACKUP)
    return paths


def test_run_backup_leaves_probation(on_probation: BoxPaths) -> None:
    assert run_backup("myapp", on_probation) == 0
    assert read_probation(on_probation) is not None


def test_backup_all_timer_leaves_probation(on_probation: BoxPaths) -> None:
    run_backup_all(on_probation)
    assert read_probation(on_probation) is not None


def test_operator_backup_ends_probation(on_probation: BoxPaths) -> None:
    with patch("boxmunge.commands.backup_cmd.BoxPaths", return_value=on_probation):
        with pytest.raises(SystemExit) as exc:
            cmd_backup(["myapp"])
    assert exc.value.code == 0
    assert read_probation(on_probation) is None


def test_mcp_backup_ends_probation(on_probation: BoxPaths) -> None:
    from boxmunge.mcp_tools import _tool_backup
    with patch("boxmunge.mcp_tools._get_paths", return_value=on_probation):
        result = _tool_backup("myapp")
    assert result["success"] is True
    assert read_probation(on_probation) is None
