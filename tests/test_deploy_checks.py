"""What a user decision means for a service's data (D16, D17, user changes)."""
from __future__ import annotations

import pytest

from boxmunge.commands import deploy_checks as dc
from boxmunge.docker_containers import ImageFacts
from boxmunge.image_probe import DirOwner
from boxmunge.release_target import production_target, staging_release_target
from boxmunge.run_as import ServiceUser, write_users

DEFAULT = ServiceUser("10001:10001", "default")
FACTS = {"app": ImageFacts("sha256:" + "a" * 64, "", ())}
S = 1048576


def _svc(*volumes, **extra):
    return {"build": ".", "image": "boxmunge.invalid/p/app", "volumes": list(volumes), **extra}


def test_mounts_from_long_and_short_syntax() -> None:
    mounts = dc.service_mounts({"volumes": [
        {"type": "volume", "source": "data", "target": "/data"},
        {"type": "volume", "target": "/anon"},
        {"type": "bind", "source": "/p/uploads", "target": "/u", "read_only": True},
        "cache:/cache", "/scratch", "./logs:/logs:ro"], "tmpfs": ["/run:size=8m"]})
    kinds = {(m.kind, m.target, m.read_only) for m in mounts}
    assert kinds == {("volume", "/data", False), ("anonymous", "/anon", False),
                     ("bind", "/u", True), ("volume", "/cache", False),
                     ("anonymous", "/scratch", False), ("bind", "/logs", True),
                     ("tmpfs", "/run", False)}


def test_image_owning_the_target_as_another_uid_is_refused() -> None:
    problems = dc.ownership_problems(
        {"app": _svc({"type": "volume", "source": "data", "target": "/data"})},
        FACTS, {"app": DEFAULT}, 0, probe=lambda image, path, offset: DirOwner(0, 0, 0o755, True))
    assert len(problems) == 1
    assert "owns as 0:0" in problems[0] and "RUN chown 10001:10001 /data" in problems[0]


@pytest.mark.parametrize("owner", [DirOwner(10001, 10001, 0o755, True), None])
def test_matching_owner_or_imageless_target_passes(owner) -> None:
    assert dc.ownership_problems(
        {"app": _svc({"type": "volume", "source": "data", "target": "/data"})},
        FACTS, {"app": DEFAULT}, 0, probe=lambda *a: owner) == []


def test_root_and_image_users_are_not_probed() -> None:
    def probe(*a):
        raise AssertionError("probed")
    for user in (ServiceUser("0:0", "manifest"), ServiceUser(None, "manifest")):
        assert dc.ownership_problems(
            {"app": _svc({"type": "volume", "source": "d", "target": "/d"})},
            FACTS, {"app": user}, 0, probe=probe) == []


def test_anonymous_data_from_compose_and_image_volume() -> None:
    facts = {"db": ImageFacts("sha256:" + "b" * 64, "", ("/var/lib/postgresql/data", "/covered"))}
    found = dc.anonymous_findings("shop", {"db": {"image": "postgres:16", "volumes": [
        "/scratch", {"type": "volume", "source": "c", "target": "/covered"}]}}, facts)
    assert [f.split(" at ")[1].split(",")[0] for f in found] == [
        "/scratch", "/var/lib/postgresql/data"]
    assert "boxmunge data adopt shop db:/scratch <name>" in found[0]


def _quiet(monkeypatch):
    monkeypatch.setattr(dc, "replacement_problems", lambda *a: [])
    monkeypatch.setattr(dc, "user_change_problems", lambda *a: [])


def test_anonymous_volumes_refuse_remapped_and_warn_otherwise(paths, monkeypatch) -> None:
    _quiet(monkeypatch)
    facts = {"db": ImageFacts("sha256:" + "b" * 64, "", ("/var/lib/postgresql/data",))}
    services = {"db": {"image": "postgres:16"}}
    users = {"db": ServiceUser(None, "manifest")}
    target = production_target(paths, "shop")
    refused, warned = dc.release_problems(paths, target, {}, services, facts, users, 0)
    assert refused == [] and "will block userns-migrate" in warned[0]
    refused, warned = dc.release_problems(paths, target, {}, services, facts, users, S)
    assert warned == [] and "anonymous volume" in refused[0]


def test_staging_leaves_production_data_checks_to_promote(paths, monkeypatch) -> None:
    def boom(*a):
        raise AssertionError("checked production's data from a stage")
    monkeypatch.setattr(dc, "replacement_problems", boom)
    monkeypatch.setattr(dc, "user_change_problems", boom)
    assert dc.release_problems(paths, staging_release_target(paths, "shop"), {},
                               {"app": _svc()}, FACTS, {"app": DEFAULT}, 0) == ([], [])


def test_empty_named_volume_replacing_a_full_anonymous_one_is_refused(paths, monkeypatch) -> None:
    anon = "c" * 64
    monkeypatch.setattr("boxmunge.docker_containers.container_mounts", lambda p: [
        ("shop-db-1", "db", {"Type": "volume", "Name": anon, "Destination": "/data"})])
    monkeypatch.setattr(dc, "volume_labels",
                        lambda n: {"com.docker.volume.anonymous": ""} if n == anon else None)
    monkeypatch.setattr(dc, "volume_is_empty", lambda label, n: n != anon)
    problems = dc.replacement_problems(production_target(paths, "shop"), {},
                                       {"db": {"volumes": ["data:/data"]}})
    assert problems and "boxmunge data adopt shop db:/data data" in problems[0]


def test_user_change_with_data_owned_by_the_old_user_is_refused(paths, monkeypatch) -> None:
    uploads = paths.project_dir("shop") / "uploads"
    uploads.mkdir(parents=True)
    monkeypatch.setattr("boxmunge.docker_containers.container_users", lambda p: {"app": ""})
    problems = dc.user_change_problems(
        paths, production_target(paths, "shop"), {},
        {"app": _svc({"type": "bind", "source": str(uploads), "target": "/u"})},
        {"app": DEFAULT}, 0)
    assert len(problems) == 1
    assert "ran as root and now resolves to 10001" in problems[0]
    assert "boxmunge data chown shop app 10001:10001" in problems[0]


def test_the_record_speaks_before_the_running_containers(paths, monkeypatch) -> None:
    uploads = paths.project_dir("shop") / "uploads"
    uploads.mkdir(parents=True)
    monkeypatch.setattr("boxmunge.docker_containers.container_users", lambda p: {"app": ""})
    write_users(paths, "shop", {"app": DEFAULT})
    assert dc.user_change_problems(
        paths, production_target(paths, "shop"), {},
        {"app": _svc({"type": "bind", "source": str(uploads), "target": "/u"})},
        {"app": DEFAULT}, 0) == []


def test_user_change_with_data_already_owned_by_the_new_user_passes(paths, monkeypatch) -> None:
    monkeypatch.setattr("boxmunge.docker_containers.container_users", lambda p: {"cache": ""})
    monkeypatch.setattr(dc, "_owner_uid", lambda target, model, mount, offset: 999)
    assert dc.user_change_problems(
        paths, production_target(paths, "shop"), {},
        {"cache": {"image": "redis:7-alpine", "volumes": ["data:/data"]}},
        {"cache": ServiceUser("999:1000", "manifest")}, 0) == []


def test_read_only_sources_must_be_world_readable_when_remapped(paths, monkeypatch) -> None:
    _quiet(monkeypatch)
    conf = paths.project_dir("shop") / "conf"
    (conf / "sub").mkdir(parents=True)
    (conf / "app.ini").write_text("x")
    (conf / "app.ini").chmod(0o600)
    (conf / "sub").chmod(0o700)
    services = {"app": {"volumes": [{"type": "bind", "source": str(conf), "target": "/c",
                                     "read_only": True}]}}
    problems = dc.readability_problems(services)
    assert len(problems) == 1 and "app.ini" in problems[0] and "sub" in problems[0]
    users = {"app": ServiceUser("0:0", "manifest")}
    target = production_target(paths, "shop")
    assert dc.release_problems(paths, target, {}, services, {}, users, 0)[0] == []
    refused, _ = dc.release_problems(paths, target, {}, services, {}, users, S)
    assert "app.ini" in refused[0]
    (conf / "sub").chmod(0o755)


def test_first_deploy_has_nothing_to_compare(paths) -> None:
    assert dc.user_change_problems(paths, production_target(paths, "new"), {},
                                   {"app": _svc("data:/data")}, {"app": DEFAULT}, 0) == []
