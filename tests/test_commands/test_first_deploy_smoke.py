"""Tests for first-deploy smoke test downgrade behaviour."""

from pathlib import Path

from boxmunge.commands.check import should_downgrade_smoke_failure
from boxmunge.paths import BoxPaths


class TestFirstDeploySmokeDowngrade:
    def test_first_deploy_returns_true(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.deploy_state.mkdir(parents=True)
        assert should_downgrade_smoke_failure("newproject", paths) is True

    def test_existing_deploy_returns_false(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.deploy_state.mkdir(parents=True)
        from boxmunge.state import write_state
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "abc123",
            "deployed_at": "2026-04-15T10:00:00Z",
        })
        assert should_downgrade_smoke_failure("myapp", paths) is False
