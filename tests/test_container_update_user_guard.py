"""A pulled image whose USER moved is held back everywhere a pull happens,
and the deploy the alert asks for decides from it."""
from __future__ import annotations

import pytest

from boxmunge import user_drift
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


@pytest.mark.decides_users
def test_the_deploy_pulls_a_held_back_image_again_and_clears_the_record(
        paths, monkeypatch) -> None:
    """No loop: the alert's deploy decides from the new image, records its
    USER, and the next container-update finds nothing to hold back."""
    from boxmunge.commands import deploy_images as di
    from boxmunge.commands.release_config import decide_release_users, generate_release_config
    paths.project_dir("shop").mkdir(parents=True)
    (paths.project_dir("shop") / "compose.yml").write_text(
        "services:\n  db:\n    image: postgres:16\n")
    paths.project_user_drift("shop").write_text('{"services": ["db"]}\n')
    pulls = []
    monkeypatch.setattr(di, "_run", lambda cmd, **kw: pulls.append(cmd))
    _facts(monkeypatch, "nginx")
    monkeypatch.setattr(di, "image_facts", lambda ref: ImageFacts("sha256:x", "nginx", ()))
    manifest = {"project": "shop", "hosts": ["shop.example.com"], "schema_version": 3,
                "services": {"web": {"port": 80, "routes": [{"path": "/"}]}},
                "user_entries": {"db": {"security": {"user": "image", "reason": "r"}}}}
    users = decide_release_users("shop", paths, manifest, "deploy")
    assert any("always" in c and c[-1] == "db" for c in pulls)
    assert users["db"].image_user == "nginx"
    generate_release_config("shop", paths, manifest, "deploy", users)
    assert user_drift.held_back(paths, "shop") == frozenset()
    assert user_drift.drift(paths, "shop", {"db": "postgres:16"}) == {}
