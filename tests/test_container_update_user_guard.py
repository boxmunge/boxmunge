"""container-update: an image whose USER changed is not recreated; alert."""
from __future__ import annotations

from boxmunge.docker_containers import ImageFacts
from boxmunge.run_as import ServiceUser, image_user_drift, write_users


def test_drift_only_for_services_running_as_the_image_user(paths, monkeypatch) -> None:
    write_users(paths, "shop", {"db": ServiceUser(None, "image", "postgres"),
                                "web": ServiceUser("10001:10001", "default", ""),
                                "app": ServiceUser("1000", "compose", ""),
                                "img": ServiceUser(None, "manifest", "")})
    monkeypatch.setattr("boxmunge.docker_containers.image_facts",
                        lambda ref: ImageFacts("sha256:x", "root", ()))
    assert image_user_drift(paths, "shop", {"db": "postgres:17", "web": "x", "app": "y",
                                            "img": "z", "new": "n"}) == [
        "db: image user postgres -> root"]


def test_same_identity_spelled_differently_is_no_drift(paths, monkeypatch) -> None:
    write_users(paths, "shop", {"db": ServiceUser(None, "manifest", "")})
    monkeypatch.setattr("boxmunge.docker_containers.image_facts",
                        lambda ref: ImageFacts("sha256:x", "0:0", ()))
    assert image_user_drift(paths, "shop", {"db": "postgres:17"}) == []


def test_container_update_refuses_and_alerts(paths, fake_containers, monkeypatch) -> None:
    import boxmunge.container_update as cu
    from boxmunge.container_update import update_target_locked
    from boxmunge.container_update_targets import UpdateTarget
    from tests.test_container_update import _NEW, FakeDocker, _write_project
    _write_project(paths, "myapp")
    docker = FakeDocker(monkeypatch, fake_containers, "myapp", {"web": "nginx:1.25"})
    docker.pulled = {"nginx:1.25": _NEW}
    write_users(paths, "myapp", {"web": ServiceUser(None, "manifest", "")})
    monkeypatch.setattr("boxmunge.docker_containers.image_facts",
                        lambda ref: ImageFacts(_NEW, "nginx", ()))
    sent = []
    monkeypatch.setattr(cu, "notify", lambda p, title, body, **kw: sent.append(title) or True)
    target = UpdateTarget(name="myapp", project_dir=paths.project_dir("myapp"),
                          compose_files=["compose.yml"], strategy="leave_broken", has_backup=False)
    result = update_target_locked(paths, target)
    assert result["status"] == "failed" and result["reason"].startswith("user_changed: web")
    assert docker.ups == 0
    assert sent == ["myapp: image user changed"]
