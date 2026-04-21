# SPDX-License-Identifier: Apache-2.0
import json
from datetime import datetime, timezone
from pathlib import Path
import pytest
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_state import (
    is_blocklisted, add_to_blocklist, remove_from_blocklist,
    read_probation, write_probation, clear_probation,
)


@pytest.fixture
def paths(tmp_path):
    p = BoxPaths(root=tmp_path / "bm")
    p.upgrade_state.mkdir(parents=True)
    return p


class TestBlocklist:
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
