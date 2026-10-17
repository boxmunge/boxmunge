"""A deploy that fails after its containers started still records that
production runs the new release, so rollback returns to the release it
replaced with the snapshot taken before this deploy (codebase review
finding 09, as it applies to git-sourced projects).

Before, the deploy state kept naming the replaced release as current, so a
git project's rollback skipped back one release further, to data from
before that release.
"""
from __future__ import annotations

from unittest.mock import patch

import yaml

from boxmunge.commands import deploy
from boxmunge.commands.rollback import find_rollback_target
from boxmunge.state import read_state, write_state

NAME = "myapp"


def _repo_project(paths, state: dict | None) -> dict:
    pdir = paths.project_dir(NAME)
    (pdir / "repo").mkdir(parents=True)
    manifest = {"project": NAME, "hosts": [f"{NAME}.example.com"],
                "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
                "backup": {"type": "postgres", "service": "web",
                           "dump_command": "d", "restore_command": "r"}}
    (pdir / "manifest.yml").write_text(yaml.safe_dump(manifest))
    for snap in ("S0", "S1", "S2"):
        (paths.project_backups(NAME)).mkdir(parents=True, exist_ok=True)
        (paths.project_backups(NAME) / snap).write_text("snapshot")
    if state is not None:
        write_state(paths.project_deploy_state(NAME), state)
    return manifest


def _start(paths, manifest, ref, snapshot, smoke=True) -> int:
    with patch.object(deploy, "compose_up_checked"), patch.object(deploy, "caddy_reload"), \
            patch.object(deploy.deploy_storage, "prepare_storage"), \
            patch.object(deploy, "post_deploy_diagnostics"), \
            patch.object(deploy, "smoke_ok", return_value=smoke):
        return deploy.replace_release(NAME, paths, manifest, ref, snapshot)


V1_LIVE = {"current_ref": "V1", "pre_deploy_snapshot": "S0",
           "history": [{"ref": "V0", "snapshot": ""}]}


def test_failed_deploy_after_start_makes_the_replaced_release_the_target(paths) -> None:
    manifest = _repo_project(paths, dict(V1_LIVE))
    assert _start(paths, manifest, "V2", "S1", smoke=False) == 1
    state = read_state(paths.project_deploy_state(NAME))
    assert state["current_ref"] == "V2"
    assert state["history"][0]["ref"] == "V1"
    target = find_rollback_target(paths, NAME)
    assert (target.ref, target.snapshot) == ("V1", "S1")


def test_retrying_the_same_release_keeps_the_snapshot_that_pairs_with_it(paths) -> None:
    """S2 holds data the failed V2 may already have migrated."""
    manifest = _repo_project(paths, dict(V1_LIVE))
    assert _start(paths, manifest, "V2", "S1", smoke=False) == 1
    assert _start(paths, manifest, "V2", "S2") == 0
    state = read_state(paths.project_deploy_state(NAME))
    assert [h["ref"] for h in state["history"]] == ["V1", "V0"]
    target = find_rollback_target(paths, NAME)
    assert (target.ref, target.snapshot) == ("V1", "S1")


def test_a_failed_first_deploy_records_nothing(paths) -> None:
    """A retry is still a first deploy (its smoke failures are downgraded)."""
    manifest = _repo_project(paths, None)
    assert _start(paths, manifest, "V1", None, smoke=False) == 1
    assert "current_ref" not in read_state(paths.project_deploy_state(NAME))

