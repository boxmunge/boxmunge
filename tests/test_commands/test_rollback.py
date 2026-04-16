"""Tests for boxmunge rollback command logic."""

import pytest
from pathlib import Path

from boxmunge.commands.rollback import find_rollback_target, RollbackTarget
from boxmunge.paths import BoxPaths
from boxmunge.state import write_state


class TestFindRollbackTarget:
    def test_finds_previous_ref_and_snapshot(self, paths: BoxPaths) -> None:
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "abc123",
            "deployed_at": "2026-03-30T14:00:00Z",
            "pre_deploy_snapshot": "myapp-2026-03-30T135955.tar.gz.age",
            "history": [
                {
                    "ref": "def456",
                    "deployed_at": "2026-03-29T10:00:00Z",
                    "snapshot": "myapp-2026-03-29T095955.tar.gz.age",
                },
            ],
        })
        target = find_rollback_target(paths, "myapp")
        assert target is not None
        assert target.previous_ref == "def456"
        assert target.snapshot == "myapp-2026-03-30T135955.tar.gz.age"

    def test_returns_none_with_no_history(self, paths: BoxPaths) -> None:
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "abc123",
            "deployed_at": "2026-03-30T14:00:00Z",
            "pre_deploy_snapshot": "",
            "history": [],
        })
        target = find_rollback_target(paths, "myapp")
        assert target is None

    def test_returns_none_with_no_state(self, paths: BoxPaths) -> None:
        target = find_rollback_target(paths, "myapp")
        assert target is None
