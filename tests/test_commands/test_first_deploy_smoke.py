"""Tests for first-deploy smoke test downgrade behaviour."""

from pathlib import Path
from unittest.mock import patch

from boxmunge.commands.check import SmokeResult, should_downgrade_smoke_failure
from boxmunge.commands.deploy import run_deploy
from boxmunge.identity import register_project_identity
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.state import write_state

from tests.bundle_helpers import manifest_text, place_bundle


class TestFirstDeploySmokeDowngrade:
    def test_first_deploy_returns_true(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.deploy_state.mkdir(parents=True)
        assert should_downgrade_smoke_failure("newproject", paths) is True

    def test_existing_deploy_returns_false(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.deploy_state.mkdir(parents=True)
        write_state(paths.project_deploy_state("myapp"), {
            "current_ref": "abc123",
            "deployed_at": "2026-04-15T10:00:00Z",
        })
        assert should_downgrade_smoke_failure("myapp", paths) is False

    def test_registered_identity_alone_is_still_a_first_deploy(self, paths) -> None:
        """D-36: deploy registers the project ULID (writing the state file)
        before the smoke test runs; that must not count as a prior deploy."""
        register_project_identity("myapp", "01TESTULID0000000000000000", paths)
        assert should_downgrade_smoke_failure("myapp", paths) is True


SMOKE_MANIFEST = manifest_text().replace(
    "      - path: /\n", "      - path: /\n    smoke: boxmunge-scripts/smoke.sh\n")


class TestDeployJoin:
    """The predicate joined to a real bundle deploy (D-36)."""

    def _deploy(self, paths, ts: str) -> int:
        place_bundle(paths, timestamp=ts, files={
            "manifest.yml": SMOKE_MANIFEST,
            "boxmunge-scripts/smoke.sh": "#!/bin/sh\nexit 1\n",
        })
        failing = SmokeResult(status="warning", message="not ready yet")
        with patch("boxmunge.commands.deploy.compose_up"), \
                patch("boxmunge.commands.deploy.caddy_reload"), \
                patch("boxmunge.commands.check.run_smoke_in_container",
                      return_value=failing):
            return run_deploy("myapp", paths)

    def test_first_bundle_deploy_downgrades_smoke_failure(self, paths, capsys) -> None:
        add_project("myapp", paths)
        assert self._deploy(paths, "2026-10-13T090000000000") == 0
        assert "first deploy" in capsys.readouterr().out

    def test_later_deploy_fails_on_smoke_failure(self, paths) -> None:
        add_project("myapp", paths)
        assert self._deploy(paths, "2026-10-13T090000000000") == 0
        assert self._deploy(paths, "2026-10-13T100000000000") == 1
