# SPDX-License-Identifier: Apache-2.0
"""Tests for probation promotion on user interaction."""

import os

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

    def test_clears_probation_file_but_not_old_venv(self, paths):
        """Deploy-user code must NOT rmtree root-owned venv dirs.

        Orphan venv cleanup is deferred to the health timer (root context)
        via boxmunge-upgrade check-probation.
        """
        write_probation(paths, "0.2.1", "a", hours=6)
        clear_probation_if_active(paths, "deploy")
        assert not paths.probation.exists()
        # Both venv dirs must survive — only root can remove them
        assert (paths.root / "env-a").exists()
        assert (paths.root / "env-b").exists()

    def test_clear_when_previous_slot_b_leaves_venvs(self, paths):
        """Same invariant holds when previous slot is b."""
        write_probation(paths, "0.2.1", "b", hours=6)
        clear_probation_if_active(paths, "rollback")
        assert not paths.probation.exists()
        assert (paths.root / "env-a").exists()
        assert (paths.root / "env-b").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
class TestUnreadableMarker:
    """#107: install.sh once left the marker root:deploy 0600. The marker is
    advisory to deploy, so an unreadable one must not abort the command."""

    def test_warns_naming_the_cause_and_carries_on(self, paths, capsys):
        write_probation(paths, "0.2.1", "a", hours=6)
        paths.probation.chmod(0)
        clear_probation_if_active(paths, "deploy")  # does not raise
        err = capsys.readouterr().err
        assert "WARNING" in err and "Cannot end the upgrade probation early" in err
        assert "Cannot read" not in err  # said once, as a warning, not also as an error
        assert str(paths.probation) in err and "Permission denied" in err
        assert f"sudo chmod 660 {paths.probation}" in err
        paths.probation.chmod(0o600)
        assert paths.probation.exists()
        log = (paths.logs / "boxmunge.log").read_text()
        assert '"level": "warn"' in log and "Cannot end the upgrade probation early" in log

    def test_a_malformed_marker_still_raises(self, paths):
        from boxmunge.upgrade_state import UpgradeStateError
        paths.probation.write_text("{not json")
        with pytest.raises(UpgradeStateError):
            clear_probation_if_active(paths, "deploy")
