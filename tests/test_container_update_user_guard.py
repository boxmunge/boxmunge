"""A pulled image whose USER moved is held back everywhere a pull happens,
and the deploy the alert asks for decides from it."""
from __future__ import annotations

import pytest

from boxmunge import user_drift
from boxmunge.commands.release_config import remove_candidates as REAL_REMOVE
from boxmunge.docker_containers import ImageFacts, LocalImage
from boxmunge.run_as import ServiceUser, write_users


def _facts(monkeypatch, user):
    monkeypatch.setattr("boxmunge.docker_containers.image_facts",
                        lambda ref: ImageFacts("sha256:x", user, ()))


def test_drift_only_for_services_running_as_the_image_user(paths, monkeypatch) -> None:
    write_users(paths, "shop", {"db": ServiceUser(None, "image", "postgres"),
                                "web": ServiceUser("10001:10001", "default", ""),
                                "app": ServiceUser("1000", "compose", ""),
                                "img": ServiceUser(None, "manifest", "")})
    _facts(monkeypatch, "root")
    assert user_drift.drift(paths, "shop", {"db": "postgres:17", "web": "x", "app": "y",
                                            "img": "z", "new": "n"}) == {
        "db": "image user postgres -> root"}


def test_same_identity_spelled_differently_is_no_drift(paths, monkeypatch) -> None:
    write_users(paths, "shop", {"db": ServiceUser(None, "manifest", "")})
    _facts(monkeypatch, "0:0")
    assert user_drift.drift(paths, "shop", {"db": "postgres:17"}) == {}


@pytest.fixture
def pulled(paths, monkeypatch):
    """postgres:16 was sha256:old; the pull moved it to sha256:new, whose USER is nginx."""
    tags = {"postgres:16": "sha256:" + "0" * 64}
    monkeypatch.setattr("boxmunge.docker_containers.local_image",
                        lambda ref: LocalImage(tags[ref], ()) if ref in tags else None)
    monkeypatch.setattr(user_drift, "tag_image", lambda src, ref: tags.__setitem__(ref, src))
    sent = []
    monkeypatch.setattr(user_drift, "notify", lambda p, title, body, **kw: sent.append(body))
    _facts(monkeypatch, "nginx")
    write_users(paths, "shop", {"db": ServiceUser(None, "manifest", "")})
    return tags, sent


def test_guard_points_the_tag_back_records_and_alerts(paths, pulled) -> None:
    tags, sent = pulled
    before = user_drift.image_ids({"db": "postgres:16"})
    tags["postgres:16"] = "sha256:" + "1" * 64  # the pull
    held = user_drift.guard_pull(paths, "shop", {"db": "postgres:16"}, before,
                                 component="resume")
    assert held == {"db": "image user root -> nginx"}
    assert tags["postgres:16"] == before["db"]
    assert user_drift.held_back(paths, "shop") == {"db"} and "deploy shop" in sent[0]


def test_container_update_refuses_and_points_every_changed_tag_back(
        paths, fake_containers, monkeypatch) -> None:
    from boxmunge.container_update import update_target_locked
    from boxmunge.container_update_targets import UpdateTarget
    from tests.test_container_update import _NEW, _OLD, FakeDocker, _write_project
    _write_project(paths, "myapp")
    docker = FakeDocker(monkeypatch, fake_containers, "myapp", {"web": "nginx:1.25"})
    docker.pulled = {"nginx:1.25": _NEW}
    write_users(paths, "myapp", {"web": ServiceUser(None, "manifest", "")})
    monkeypatch.setattr("boxmunge.docker_containers.image_facts",
                        lambda ref: ImageFacts(_NEW, "nginx", ()))
    monkeypatch.setattr("boxmunge.user_drift.tag_image", docker._tag)
    monkeypatch.setattr(user_drift, "notify", lambda *a, **kw: True)
    target = UpdateTarget(name="myapp", project_dir=paths.project_dir("myapp"),
                          compose_files=["compose.yml"], strategy="leave_broken", has_backup=False)
    result = update_target_locked(paths, target)
    assert result["status"] == "failed" and result["reason"].startswith("user_changed: web")
    assert docker.ups == 0 and docker.tags["nginx:1.25"] == _OLD
    assert user_drift.held_back(paths, "myapp") == {"web"}


OLD, NEW = "sha256:" + "0" * 64, "sha256:" + "1" * 64
CANDIDATE = "boxmunge.invalid/shop/db:boxmunge-candidate"


@pytest.fixture
def registry(paths, monkeypatch):
    """A box whose postgres:16 runs OLD; pulling it again fetches NEW, whose
    USER is nginx. Tags and docker tag/rm/pull act on one dict."""
    from boxmunge.commands import deploy_images as di
    from boxmunge.commands import release_config as rc
    tags = {"postgres:16": OLD}

    def run(cmd, **kw):
        import subprocess
        if cmd[:3] == ["docker", "image", "ls"]:
            found = "\n".join(r for r in tags if r.endswith(":boxmunge-candidate"))
            return subprocess.CompletedProcess(cmd, 0, found, "")
        if "pull" in cmd:
            tags["postgres:16"] = NEW
        elif cmd[:2] == ["docker", "tag"]:
            tags[cmd[3]] = tags.get(cmd[2], cmd[2])
        elif cmd[:3] == ["docker", "image", "rm"]:
            for ref in cmd[3:]:
                tags.pop(ref, None)
    for mod in (di, rc):
        monkeypatch.setattr(mod, "_run", run)
    monkeypatch.setattr("boxmunge.docker_containers.local_image",
                        lambda ref: LocalImage(tags[ref], ()) if ref in tags else None)
    def facts(ref):
        return ImageFacts(tags[ref], "nginx" if tags[ref] == NEW else "", ())
    monkeypatch.setattr(di, "image_facts", facts)
    monkeypatch.setattr("boxmunge.docker_containers.image_facts", facts)
    paths.project_dir("shop").mkdir(parents=True)
    (paths.project_dir("shop") / "compose.yml").write_text(
        "services:\n  db:\n    image: postgres:16\n")
    paths.project_user_drift("shop").write_text('{"services": ["db"]}\n')
    return tags


def _manifest(declared: bool) -> dict:
    entries = {"db": {"security": {"user": "image", "reason": "r"}}} if declared else {}
    return {"project": "shop", "hosts": ["shop.example.com"], "schema_version": 3,
            "services": {"web": {"port": 80, "routes": [{"path": "/"}]}},
            "user_entries": entries}


@pytest.mark.decides_users
def test_the_deploy_decides_from_the_held_back_image_and_names_it_only_at_the_switch(
        paths, registry) -> None:
    """No loop: the alert's deploy decides from the new image; the real tag
    moves only when the release switches, and nothing is held back then."""
    from boxmunge.commands.release_config import (
        decide_release_users, generate_release_config, promote_candidates,
    )
    users = decide_release_users("shop", paths, _manifest(True), "deploy")
    assert users["db"].image_user == "nginx"
    assert registry["postgres:16"] == OLD and registry[CANDIDATE] == NEW
    generate_release_config("shop", paths, _manifest(True), "deploy", users)
    assert user_drift.held_back(paths, "shop") == {"db"}  # until the switch
    promote_candidates(paths, "shop")
    assert registry["postgres:16"] == NEW and CANDIDATE not in registry
    assert user_drift.held_back(paths, "shop") == frozenset()
    assert user_drift.drift(paths, "shop", {"db": "postgres:16"}) == {}


@pytest.mark.decides_users
def test_a_refused_deploy_leaves_the_running_image_named(paths, registry, monkeypatch) -> None:
    """Refused (the new image runs as root, undeclared), then abandoned: a
    later restart still finds the tag naming the image that ran."""
    from boxmunge.commands import deploy_images as di
    from boxmunge.commands import release_config as rc
    from boxmunge.release_target import DeployRefused
    monkeypatch.setattr(di, "image_facts", lambda ref: ImageFacts(registry[ref], "", ()))
    with pytest.raises(DeployRefused):
        rc.decide_release_users("shop", paths, _manifest(False), "deploy")
    assert registry["postgres:16"] == OLD
    REAL_REMOVE("shop")  # what abandon and the next deploy do
    assert CANDIDATE not in registry


def test_abandon_removes_the_candidates(paths, monkeypatch) -> None:
    from boxmunge.commands import install_abandon, release_config
    removed = []
    monkeypatch.setattr(release_config, "remove_candidates", removed.append)
    monkeypatch.setattr(install_abandon, "restore_superseded", lambda *a: None)
    from tests.bundle_helpers import place_bundle
    from boxmunge.project_registry import add_project
    from boxmunge.commands.deploy import run_deploy
    from tests.txn_helpers import docker_off
    from unittest.mock import patch
    add_project("myapp", paths)
    place_bundle(paths, timestamp="2026-10-16T090000000000")
    with docker_off(), patch("boxmunge.commands.deploy_tree.decide_release_users",
                             side_effect=__import__("boxmunge.release_target", fromlist=["x"])
                             .DeployRefused(["no"])):
        assert run_deploy("myapp", paths, ref="2026-10-16T090000000000") == 1
    assert install_abandon.run_abandon("myapp", paths) == 0
    assert removed == ["myapp"]
