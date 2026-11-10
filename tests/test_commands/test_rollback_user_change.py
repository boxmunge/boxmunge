"""L-02: a rollback refused because the restored release would run a
service as another user than the one that owns its data (after `data
chown` and a deploy as the new user) names the way out of a rollback: give
the data back with `data chown`, then run the rollback again. Not "before
deploying again", nor redeclaring the user: the restored release is an old
one, its declaration is what it is."""
from __future__ import annotations

import pytest

from boxmunge.commands import deploy_checks
from boxmunge.docker_containers import ImageFacts
from boxmunge.paths import BoxPaths
from boxmunge.release_target import ReleaseTarget
from boxmunge.run_as import SOURCE_CHOWN, ServiceUser, write_users
from boxmunge.staged_release import ComposeTarget


@pytest.fixture
def case(paths: BoxPaths, monkeypatch):
    (paths.project_dir("shop") / "data").mkdir(parents=True)
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    write_users(paths, "shop", {"app": ServiceUser("10002:10002", SOURCE_CHOWN, "root")})
    services = {"app": {"image": "busybox", "user": "10001:10001", "volumes": [
        {"type": "bind", "source": str(paths.project_dir("shop") / "data"), "target": "/data"}]}}
    users = {"app": ServiceUser("10001:10001", "compose", "root")}
    target = ReleaseTarget("shop", ComposeTarget(paths.project_dir("shop"), "shop",
                                                 ["compose.yml"]))
    monkeypatch.setattr(deploy_checks.docker_containers, "container_users", lambda p: {})
    monkeypatch.setattr(deploy_checks, "_owner_uid", lambda *a: 10002)
    return paths, target, services, users


def test_a_rollback_names_data_chown_then_rollback(case) -> None:
    paths, target, services, users = case
    [problem] = deploy_checks.user_change_problems(paths, target, {}, services, users, 0,
                                                   rerun="boxmunge rollback shop")
    assert "`boxmunge data chown shop app 10001:10001`, then run `boxmunge rollback shop` " \
           "again" in problem
    assert "deploying again" not in problem and "security.user" not in problem


def test_a_deploy_still_names_deploying_again(case) -> None:
    paths, target, services, users = case
    [problem] = deploy_checks.user_change_problems(paths, target, {}, services, users, 0)
    assert "data chown shop app 10001:10001` before deploying again" in problem


@pytest.mark.decides_users
def test_prepare_release_users_passes_the_rollback_rerun(paths, monkeypatch) -> None:
    from boxmunge.commands import deploy_images
    seen = {}

    def release_problems(*args, rerun=None):
        seen["rerun"] = rerun
        return [], []
    monkeypatch.setattr(deploy_images.deploy_checks, "release_problems", release_problems)
    monkeypatch.setattr(deploy_images, "resolved_services", lambda t: ({}, {}))
    monkeypatch.setattr(deploy_images, "build_and_pull", lambda *a, **k: {})
    monkeypatch.setattr(deploy_images, "read_users",
                        lambda *a, **k: {"app": ServiceUser("1:1", SOURCE_CHOWN, "root")})
    monkeypatch.setattr(deploy_images, "decide_users", lambda *a: ({}, []))
    monkeypatch.setattr(deploy_images, "remap_offset", lambda p: 0)
    monkeypatch.setattr(deploy_images, "compose_users", lambda t: {})
    target = ReleaseTarget("shop", ComposeTarget(paths.project_dir("shop"), "shop", []))
    deploy_images.prepare_release_users(paths, target, {}, component="rollback", pull=False,
                                        rollback=True)
    assert seen["rerun"] == "boxmunge rollback shop"
    deploy_images.prepare_release_users(paths, target, {}, component="deploy", pull=False)
    assert seen["rerun"] is None
