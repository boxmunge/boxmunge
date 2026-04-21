# SPDX-License-Identifier: Apache-2.0
"""Tests for probation promotion on user interaction."""

import shutil
from pathlib import Path
import pytest
from boxmunge.paths import BoxPaths
from boxmunge.probation import clear_probation_if_active
from boxmunge.upgrade_state import write_probation


@pytest.fixture
def paths(tmp_path):
    p = BoxPaths(root=tmp_path / "bm")
    p.upgrade_state.mkdir(parents=True)
    (p.root / "env-a").mkdir(parents=True)
    (p.root / "env-b").mkdir(parents=True)
    p.logs.mkdir(parents=True)  # needed for log_operation
    return p


class TestClearProbationIfActive:
    def test_noop_when_no_probation(self, paths):
        clear_probation_if_active(paths, "deploy")
        assert not paths.probation.exists()

    def test_clears_probation_and_deletes_old_venv(self, paths):
        write_probation(paths, "0.2.1", "a", hours=6)
        clear_probation_if_active(paths, "deploy")
        assert not paths.probation.exists()
        assert not (paths.root / "env-a").exists()
        assert (paths.root / "env-b").exists()

    def test_clear_when_previous_slot_b(self, paths):
        write_probation(paths, "0.2.1", "b", hours=6)
        clear_probation_if_active(paths, "rollback")
        assert not paths.probation.exists()
        assert (paths.root / "env-a").exists()
        assert not (paths.root / "env-b").exists()
