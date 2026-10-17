# SPDX-License-Identifier: Apache-2.0
"""Git staging against real Docker and Compose (spec Test plan,
Integration, Git): stage SHA A while production runs B, with production's
HEAD and work tree unchanged; promote deploys exactly A after the branch
moved; unstage leaves B. The project's compose.yml lives in the
repository, linked from the project dir as add-git-project does, and
mounts and builds from ./repo/: in the slot that is the staged clone.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.project_registry import add_project
from boxmunge.staged_release import load_slot, release_dir, slot_dir, staging_target
from boxmunge.staging_isolation import production_model, staging_model
from tests.bundle_helpers import manifest_text
from tests.git_helpers import commit, git, origin_with
from tests.integration.docker_images import BUSYBOX, docker, ensure_busybox
from tests.integration.slot_release import no_caddy, production_files, remove, working_dir

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
    pytest.mark.usefixtures("helper_image"),
]
_LOOP = ["sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"]


def _files(name: str, origin, version: str, *, build: bool = False) -> dict[str, str]:
    manifest = yaml.safe_load(manifest_text(name, image_users=True))
    manifest.update(schema_version=3, source="git", repo=str(origin), ref="main")
    manifest["services"] = {"app": {"internal": True, "writable": {"external": True}}}
    app = {"command": _LOOP, "network_mode": "none", "environment": {"VERSION": version},
           "volumes": ["./repo/appconfig:/etc/app:ro"]}
    app.update({"build": {"context": "./repo/img"}} if build else {"image": BUSYBOX})
    return {"manifest.yml": yaml.safe_dump(manifest),
            "compose.yml": yaml.safe_dump({"services": {"app": app}}),
            "appconfig/settings": version, "img/Dockerfile": f"FROM {BUSYBOX}\n"}


@contextmanager
def git_slot_project(paths, tmp_path, *, build: bool = False):
    """(name, project dir, work clone, sha of v1): deployed at v1."""
    ensure_busybox()
    name = f"bmgit{uuid.uuid4().hex[:8]}"
    origin, work = origin_with(tmp_path, {"README": "x\n"})
    v1 = commit(work, _files(name, origin, "v1", build=build), "v1")
    add_project(name, paths)
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    git("clone", "-q", str(origin), str(pdir / "repo"), cwd=tmp_path)
    for link in ("compose.yml", "manifest.yml"):
        os.symlink(pdir / "repo" / link, pdir / link)
    try:
        yield name, pdir, work, origin, v1
    finally:
        remove(f"{name}-staging")
        remove(name)


def _runs(container: str, version: str) -> bool:
    env = dict(p.split("=", 1) for p in json.loads(
        docker("inspect", "--format", "{{json .Config.Env}}", container)))
    return (env["VERSION"], docker("exec", container, "cat", "/etc/app/settings")) == \
        (version, version)


def _production(paths, name: str) -> dict:
    """Production's files, but not repo/.git: the stage's fetch adds origin's
    objects and refs there (as a deploy does), never HEAD or the work tree."""
    return {k: v for k, v in production_files(paths, name).items()
            if not k.startswith("repo/.git/")}


def _head(pdir) -> str:
    return git("rev-parse", "HEAD", cwd=pdir / "repo")


def test_stage_a_while_production_runs_b_then_promote_exactly_a(paths, tmp_path) -> None:
    with git_slot_project(paths, tmp_path) as (name, pdir, work, origin, v1), no_caddy():
        assert run_deploy(name, paths) == 0
        assert _head(pdir) == v1 and _runs(f"{name}-app-1", "v1")
        v2 = commit(work, _files(name, origin, "v2"), "v2")
        before = _production(paths, name)
        assert run_stage(name, paths) == 0
        assert load_slot(paths, name).ref == v2
        assert _runs(f"{name}-staging-app-1", "v2") and _runs(f"{name}-app-1", "v1")
        assert working_dir(f"{name}-staging-app-1") == str(release_dir(slot_dir(paths, name)))
        assert _head(pdir) == v1 and git("status", "--porcelain", cwd=pdir / "repo") == ""
        assert _production(paths, name) == before
        commit(work, _files(name, origin, "v3"), "v3")    # the branch moves on
        assert run_promote(name, paths) == 0
        assert _head(pdir) == v2 and _runs(f"{name}-app-1", "v2")
        assert load_slot(paths, name) is None
        assert not docker("ps", "-aq", "--filter",
                          f"label=com.docker.compose.project={name}-staging")


def test_unstage_leaves_production_at_its_commit(paths, tmp_path) -> None:
    with git_slot_project(paths, tmp_path) as (name, pdir, work, origin, v1), no_caddy():
        assert run_deploy(name, paths) == 0
        commit(work, _files(name, origin, "v2"), "v2")
        assert run_stage(name, paths) == 0
        assert run_unstage(name, paths) == 0
        assert _head(pdir) == v1 and _runs(f"{name}-app-1", "v1")
        assert load_slot(paths, name) is None


def test_a_git_deploy_during_a_stage_keeps_staging_running(paths, tmp_path) -> None:
    with git_slot_project(paths, tmp_path) as (name, pdir, work, origin, v1), no_caddy():
        assert run_deploy(name, paths) == 0
        v2 = commit(work, _files(name, origin, "v2"), "v2")
        assert run_stage(name, paths) == 0
        staged = docker("inspect", "--format", "{{.Id}} {{.State.StartedAt}}",
                        f"{name}-staging-app-1")
        hotfix = commit(work, _files(name, origin, "hotfix"), "hotfix")
        assert run_deploy(name, paths) == 0
        assert _head(pdir) == hotfix and _runs(f"{name}-app-1", "hotfix")
        assert docker("inspect", "--format", "{{.Id}} {{.State.StartedAt}}",
                      f"{name}-staging-app-1") == staged
        assert _runs(f"{name}-staging-app-1", "v2") and load_slot(paths, name).ref == v2


def test_a_git_slot_builds_from_its_own_clone(paths, tmp_path) -> None:
    """build: is resolved, not built: no image is made."""
    with git_slot_project(paths, tmp_path, build=True) as (name, pdir, work, origin, _v1), \
            no_caddy(), patch("boxmunge.compose_guard.compose_up"):
        assert run_deploy(name, paths) == 0
        commit(work, _files(name, origin, "v2", build=True), "v2")
        assert run_stage(name, paths) == 0
        staged = staging_model(staging_target(paths, name))["services"]["app"]
        live = production_model(paths, name)["services"]["app"]
    slot_release = release_dir(slot_dir(paths, name))
    assert staged["build"]["context"] == str(slot_release / "repo" / "img")
    assert live["build"]["context"] == str(pdir / "repo" / "img")
    assert {v["source"] for v in staged["volumes"]} == {str(slot_release / "repo" / "appconfig")}
