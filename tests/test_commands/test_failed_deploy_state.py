"""A deploy that fails after its containers started still records that
production runs the new release, so rollback returns to the release it
replaced with the snapshot taken before this deploy (codebase review
finding 09, as it applies to git-sourced projects).

Before, the deploy state kept naming the replaced release as current, so a
git project's rollback skipped back one release further, to data from
before that release.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import yaml

from boxmunge.commands import deploy
from boxmunge.commands.rollback import find_rollback_target
from boxmunge.state import read_state, write_state
from tests.git_helpers import commit, git, origin_with

NAME = "myapp"


def _repo_project(paths, tmp_path, state: dict | None) -> tuple[dict, dict[str, str]]:
    """A git project whose commits V0..V2 each carry a postgres manifest:
    (manifest, {name: SHA}). ``state`` names refs V0..V2; they are recorded
    as those commits' SHAs."""
    manifest = {"project": NAME, "hosts": [f"{NAME}.example.com"],
                "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
                "backup": {"type": "postgres", "service": "web",
                           "dump_command": "d", "restore_command": "r"}}
    origin, work = origin_with(tmp_path, {"manifest.yml": yaml.safe_dump(manifest)})
    shas = {"V0": git("rev-parse", "HEAD", cwd=work)}
    shas["V1"] = commit(work, {"f": "1"}, "V1")
    shas["V2"] = commit(work, {"f": "2"}, "V2")
    pdir = paths.project_dir(NAME)
    pdir.mkdir(parents=True)
    git("clone", "-q", str(origin), str(pdir / "repo"), cwd=tmp_path)
    os.symlink(pdir / "repo" / "manifest.yml", pdir / "manifest.yml")
    for snap in ("S0", "S1", "S2"):
        (paths.project_backups(NAME)).mkdir(parents=True, exist_ok=True)
        (paths.project_backups(NAME) / snap).write_text("snapshot")
    if state is not None:
        write_state(paths.project_deploy_state(NAME), _named(state, shas))
    return manifest, shas


def _named(state: dict, shas: dict[str, str]) -> dict:
    return {**state, "current_ref": shas[state["current_ref"]],
            "history": [{**h, "ref": shas[h["ref"]]} for h in state["history"]]}


def _start(paths, manifest, ref, snapshot, smoke=True) -> int:
    with patch.object(deploy, "compose_up_checked"), patch.object(deploy, "caddy_reload"), \
            patch.object(deploy.deploy_storage, "prepare_storage"), \
            patch.object(deploy, "promote_candidates"), \
            patch.object(deploy, "post_deploy_diagnostics"), \
            patch.object(deploy, "smoke_ok", return_value=smoke):
        return deploy.replace_release(NAME, paths, manifest, ref, snapshot)


V1_LIVE = {"current_ref": "V1", "pre_deploy_snapshot": "S0",
           "history": [{"ref": "V0", "snapshot": ""}]}


def test_failed_deploy_after_start_makes_the_replaced_release_the_target(paths,
                                                                        tmp_path) -> None:
    manifest, shas = _repo_project(paths, tmp_path, dict(V1_LIVE))
    assert _start(paths, manifest, shas["V2"], "S1", smoke=False) == 1
    state = read_state(paths.project_deploy_state(NAME))
    assert state["current_ref"] == shas["V2"]
    assert state["history"][0]["ref"] == shas["V1"]
    target = find_rollback_target(paths, NAME)
    assert (target.ref, target.snapshot) == (shas["V1"], "S1")


def test_retrying_the_same_release_keeps_the_snapshot_that_pairs_with_it(paths,
                                                                        tmp_path) -> None:
    """S2 holds data the failed V2 may already have migrated."""
    manifest, shas = _repo_project(paths, tmp_path, dict(V1_LIVE))
    assert _start(paths, manifest, shas["V2"], "S1", smoke=False) == 1
    assert _start(paths, manifest, shas["V2"], "S2") == 0
    state = read_state(paths.project_deploy_state(NAME))
    assert [h["ref"] for h in state["history"]] == [shas["V1"], shas["V0"]]
    target = find_rollback_target(paths, NAME)
    assert (target.ref, target.snapshot) == (shas["V1"], "S1")


def test_a_failed_first_deploy_records_nothing(paths, tmp_path) -> None:
    """A retry is still a first deploy (its smoke failures are downgraded)."""
    manifest, shas = _repo_project(paths, tmp_path, None)
    assert _start(paths, manifest, shas["V1"], None, smoke=False) == 1
    assert "current_ref" not in read_state(paths.project_deploy_state(NAME))

