"""Tests for project identity and collision detection."""
import pytest
from boxmunge.identity import check_project_identity, register_project_identity
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state


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
        register_project_identity("existing_app", "01AAA", paths)
        with pytest.raises(ValueError, match="already registered"):
            check_project_identity("new_app", "01AAA", paths)
