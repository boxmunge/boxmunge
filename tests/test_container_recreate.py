# SPDX-License-Identifier: Apache-2.0
"""recreate_project refuses to start a project the platform keeps down;
only autofix's dark patch starts one quarantined for that patch."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge import container_recreate
from boxmunge.compose_guard import ComposeRefused
from boxmunge.container_recreate import recreate_project, start_refusal
from boxmunge.pause import write_paused_state
from tests.test_commands.cve_helpers import seed_quarantine

NAME = "shop"
PROD = ["compose.yml", "compose.boxmunge.yml"]


@pytest.fixture
def box(paths):
    paths.project_dir(NAME).mkdir(parents=True, exist_ok=True)
    with patch.object(container_recreate, "compose_up_checked") as up:
        yield paths, up


def test_free_project_is_recreated(box) -> None:
    paths, up = box
    recreate_project(paths, NAME, PROD, component="test")
    up.assert_called_once()


@pytest.mark.parametrize("dark", [False, True])
def test_paused_project_is_refused(box, dark) -> None:
    paths, up = box
    write_paused_state(NAME, paths)
    with pytest.raises(ComposeRefused, match="paused"):
        recreate_project(paths, NAME, PROD, component="test", quarantined_for_patch=dark)
    up.assert_not_called()


def test_quarantine_refused_unless_for_the_patch(box) -> None:
    paths, up = box
    seed_quarantine(paths, NAME)
    with pytest.raises(ComposeRefused, match="CVE-quarantined"):
        recreate_project(paths, NAME, PROD, component="test")
    up.assert_not_called()
    recreate_project(paths, NAME, PROD, component="test", quarantined_for_patch=True)
    up.assert_called_once()


def test_quarantined_and_paused_is_refused_even_for_the_patch(box) -> None:
    paths, up = box
    seed_quarantine(paths, NAME)
    write_paused_state(NAME, paths)
    assert "paused as well" in start_refusal(paths, NAME, quarantined_for_patch=True)


def test_monitor_stopped_project_is_refused(box) -> None:
    paths, up = box
    with patch.object(container_recreate, "is_monitor_stopped", return_value=True):
        with pytest.raises(ComposeRefused, match="health monitor"):
            recreate_project(paths, NAME, PROD, component="test", quarantined_for_patch=True)
    up.assert_not_called()
