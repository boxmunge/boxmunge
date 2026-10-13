"""system/compose.yml must agree with system_container.system_mounts()."""

from pathlib import Path

import yaml

from boxmunge.paths import BoxPaths
from boxmunge.system_container import system_mounts

COMPOSE = Path(__file__).resolve().parents[1] / "system" / "compose.yml"


def _service() -> dict:
    return yaml.safe_load(COMPOSE.read_text())["services"]["system"]


def test_mount_targets_match_the_translation_table(tmp_path) -> None:
    targets = {v["target"] for v in _service()["volumes"]}
    assert targets == {m.container for m in system_mounts(BoxPaths(root=tmp_path))}


def test_missing_host_paths_fail_instead_of_being_created() -> None:
    for v in _service()["volumes"]:
        assert v["type"] == "bind"
        assert v["bind"]["create_host_path"] is False, v["target"]


def test_only_projects_is_writable() -> None:
    writable = {v["target"] for v in _service()["volumes"] if not v.get("read_only")}
    assert writable == {"/projects"}


def test_runs_as_the_deploy_uid_from_install() -> None:
    """C-12: the uid is set at start time from the deploy user, not baked in."""
    user = _service()["user"]
    assert user.startswith("${BOXMUNGE_UID:?")
    assert ":${BOXMUNGE_GID:?" in user
