"""Tests for project identity and collision detection."""
from unittest.mock import patch

import pytest
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.deploy_steps import record_deploy_state
from boxmunge.identity import check_project_identity, register_project_identity
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.state import read_state

from tests.bundle_helpers import manifest_text, place_bundle, tree_snapshot


class TestProjectIdentity:
    def test_new_project_passes(self, paths: BoxPaths) -> None:
        check_project_identity("myapp", "01AAA", paths)  # should not raise

    def test_matching_id_passes(self, paths: BoxPaths) -> None:
        register_project_identity("myapp", "01AAA", paths)
        check_project_identity("myapp", "01AAA", paths)  # should not raise

    def test_mismatched_id_raises(self, paths: BoxPaths) -> None:
        register_project_identity("myapp", "01AAA", paths)
        with pytest.raises(ValueError, match="already registered with a different ID"):
            check_project_identity("myapp", "01BBB", paths)

    def test_no_id_in_manifest_skips_check(self, paths: BoxPaths) -> None:
        register_project_identity("myapp", "01AAA", paths)
        check_project_identity("myapp", "", paths)  # empty id — skip check

    def test_register_stores_id(self, paths: BoxPaths) -> None:
        register_project_identity("myapp", "01AAA", paths)
        state = read_state(paths.project_deploy_state("myapp"))
        assert state["project_id"] == "01AAA"

    def test_ulid_registered_under_different_name_raises(self, paths: BoxPaths) -> None:
        register_project_identity("existing-app", "01AAA", paths)
        with pytest.raises(ValueError, match="already registered"):
            check_project_identity("new-app", "01AAA", paths)


class TestDeployStatePreservesIdentity:
    """C-08: record_deploy_state rebuilt the state from scratch and dropped
    project_id, so after the first deploy the collision guard always passed."""

    def test_record_deploy_state_keeps_project_id(self, paths: BoxPaths) -> None:
        register_project_identity("myapp", "01AAA", paths)
        record_deploy_state(paths, "myapp", "myapp-2026-10-13T100000000000", None)
        with pytest.raises(ValueError, match="different ID"):
            check_project_identity("myapp", "01BBB", paths)

    def test_reverse_collision_survives_deploys(self, paths: BoxPaths) -> None:
        register_project_identity("existing-app", "01AAA", paths)
        record_deploy_state(paths, "existing-app", "ref1", None)
        record_deploy_state(paths, "existing-app", "ref2", None)
        with pytest.raises(ValueError, match="already registered"):
            check_project_identity("new-app", "01AAA", paths)

    def test_redeploy_with_a_different_ulid_is_refused(self, paths: BoxPaths, capsys) -> None:
        add_project("myapp", paths)
        place_bundle(paths, timestamp="2026-10-13T090000000000")
        with patch("boxmunge.commands.deploy.compose_up"), \
                patch("boxmunge.commands.deploy.caddy_reload"):
            assert run_deploy("myapp", paths) == 0
        before = tree_snapshot(paths.project_dir("myapp"))
        place_bundle(paths, timestamp="2026-10-13T100000000000",
                     files={"manifest.yml": manifest_text(ulid="01OTHERULID000000000000000")})
        assert run_deploy("myapp", paths) == 1
        assert "different ID" in capsys.readouterr().err
        assert tree_snapshot(paths.project_dir("myapp")) == before
