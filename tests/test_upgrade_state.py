# SPDX-License-Identifier: Apache-2.0
import json
import stat

import pytest
from boxmunge.paths import BoxPaths
import os

from boxmunge import upgrade_state
from boxmunge.upgrade_state import (
    UpgradeStateError, UpgradeStateUnreadable, is_blocklisted, add_to_blocklist, remove_from_blocklist,
    read_probation, write_probation, clear_probation,
)


@pytest.fixture
def paths(tmp_path):
    p = BoxPaths(root=tmp_path / "bm")
    p.upgrade_state.mkdir(parents=True)
    return p


class TestBlocklist:
    @pytest.mark.parametrize("content,problem", [
        ("{not json", "is not valid JSON"),
        ('["0.2.1"]', "is not a JSON object"),
    ])
    def test_unreadable_blocklist_names_the_file(self, paths, content, problem):
        paths.blocklist.write_text(content)
        for call in (lambda: is_blocklisted(paths, "0.2.1"),
                     lambda: add_to_blocklist(paths, "0.2.1", "x")):
            with pytest.raises(UpgradeStateError) as e:
                call()
            assert str(paths.blocklist) in str(e.value) and problem in str(e.value)
        assert paths.blocklist.read_text() == content

    def test_empty_blocklist_returns_false(self, paths):
        assert is_blocklisted(paths, "0.2.1") is False

    def test_add_and_check(self, paths):
        add_to_blocklist(paths, "0.2.1", "preflight_failed: import")
        assert is_blocklisted(paths, "0.2.1") is True

    def test_different_version_not_blocked(self, paths):
        add_to_blocklist(paths, "0.2.1", "health_probation")
        assert is_blocklisted(paths, "0.2.2") is False

    def test_remove_from_blocklist(self, paths):
        add_to_blocklist(paths, "0.2.1", "apply")
        remove_from_blocklist(paths, "0.2.1")
        assert is_blocklisted(paths, "0.2.1") is False

    def test_blocklist_persists_across_reads(self, paths):
        add_to_blocklist(paths, "0.2.1", "health_immediate")
        assert is_blocklisted(paths, "0.2.1") is True

    def test_add_records_reason_and_timestamp(self, paths):
        add_to_blocklist(paths, "0.2.1", "health_probation")
        data = json.loads(paths.blocklist.read_text())
        assert data["0.2.1"]["reason"] == "health_probation"
        assert "failed_at" in data["0.2.1"]


class TestProbation:
    def test_no_probation_returns_none(self, paths):
        assert read_probation(paths) is None

    def test_write_and_read(self, paths):
        write_probation(paths, "0.2.1", "a", hours=6)
        prob = read_probation(paths)
        assert prob is not None
        assert prob["version"] == "0.2.1"
        assert prob["previous_slot"] == "a"
        assert "started_at" in prob
        assert "expires_at" in prob

    def test_clear_probation(self, paths):
        write_probation(paths, "0.2.1", "a", hours=6)
        clear_probation(paths)
        assert read_probation(paths) is None

    def test_clear_when_no_probation_is_noop(self, paths):
        clear_probation(paths)
        assert read_probation(paths) is None

    def test_probation_is_group_readable_for_deploy(self, paths):
        """deploy reads (and ends) the marker root writes (#107)."""
        write_probation(paths, "0.2.1", "a", hours=6)
        assert stat.S_IMODE(paths.probation.stat().st_mode) == 0o660

    def test_probation_written_by_root_is_root_deploy(self, paths, monkeypatch):
        seen = {}
        monkeypatch.setattr(upgrade_state, "running_as_root", lambda: True)
        monkeypatch.setattr(upgrade_state, "deploy_ids", lambda: (1001, 1002))
        monkeypatch.setattr(upgrade_state, "atomic_write_bytes",
                            lambda path, text, **kw: seen.update(kw))
        write_probation(paths, "0.2.1", "a", hours=6)
        assert seen == {"mode": 0o660, "owner": (0, 1002)}

    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
    def test_unreadable_probation_is_its_own_error(self, paths):
        write_probation(paths, "0.2.1", "a", hours=6)
        paths.probation.chmod(0)
        with pytest.raises(UpgradeStateUnreadable) as e:
            read_probation(paths)
        assert str(paths.probation) in str(e.value)
