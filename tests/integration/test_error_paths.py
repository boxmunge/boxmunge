"""Integration tests for error paths -- verifying clean failures."""

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.rollback import run_rollback
from boxmunge.paths import BoxPaths


pytestmark = [pytest.mark.integration]


class TestErrorPaths:
    def test_deploy_invalid_manifest_fails_cleanly(self, int_paths: BoxPaths) -> None:
        """Deploy with an invalid manifest returns error, no state change."""
        project_name = "badproject"
        project_dir = int_paths.project_dir(project_name)
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "manifest.yml").write_text(
            "project: badproject\n"
            "# Missing required fields\n"
        )

        result = run_deploy(project_name, int_paths)
        assert result == 1

        state_path = int_paths.project_deploy_state(project_name)
        assert not state_path.exists()

    def test_rollback_no_history_fails_cleanly(self, int_paths: BoxPaths) -> None:
        """Rollback with no deploy history returns a clear error."""
        result = run_rollback("nonexistent", int_paths, yes=True)
        assert result == 1

    def test_deploy_nonexistent_project_no_bundle(self, int_paths: BoxPaths) -> None:
        """Deploy a project that doesn't exist and has no bundle fails cleanly."""
        result = run_deploy("doesnotexist", int_paths)
        assert result == 1
