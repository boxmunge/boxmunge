"""prepare_release_users decides, checks, then records; deploy, the install
transaction, rollback and stage stop on a refusal."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.commands import deploy_images as di
from boxmunge.commands.deploy import run_deploy
from boxmunge.docker_containers import ImageFacts
from boxmunge.project_registry import add_project
from boxmunge.release_target import DeployRefused, production_target
from boxmunge.release_txn import load_txn
from boxmunge.run_as import ServiceUser, read_users, write_users
from tests.bundle_helpers import manifest_text, place_bundle
from tests.txn_helpers import docker_off

pytestmark = pytest.mark.decides_users

MANIFEST = {"project": "shop", "services": {"web": {"port": 8080}}}
DB_IMAGE = {"internal": True, "security": {"user": "image", "reason": "drops to postgres"}}
V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"


@pytest.fixture
def images(monkeypatch):
    """No builds or pulls; every image sets no USER."""
    built: list[list[str]] = []
    monkeypatch.setattr(di, "build_and_pull", lambda target, s: built.append(sorted(s)))
    monkeypatch.setattr(di, "image_facts", lambda ref: ImageFacts("sha256:" + "a" * 64, "", ()))
    return built


def _resolved(monkeypatch, services):
    monkeypatch.setattr(di, "resolved_services", lambda target: ({}, services))


SERVICES = {"web": {"build": ".", "image": "boxmunge.invalid/shop/web"},
            "db": {"image": "postgres:16"}}


def test_every_root_registry_service_is_listed_and_nothing_recorded(
        paths, images, monkeypatch) -> None:
    _resolved(monkeypatch, {**SERVICES, "cache": {"image": "redis:7"}})
    with pytest.raises(DeployRefused) as e:
        di.prepare_release_users(paths, production_target(paths, "shop"), MANIFEST,
                                 component="deploy")
    assert len(e.value.problems) == 2  # cache and db, both named
    assert read_users(paths, "shop") == {}


def test_decisions_are_recorded_and_opt_outs_logged(paths, images, monkeypatch) -> None:
    _resolved(monkeypatch, SERVICES)
    manifest = {**MANIFEST, "services": {**MANIFEST["services"], "db": DB_IMAGE}}
    users = di.prepare_release_users(paths, production_target(paths, "shop"), manifest,
                                     component="deploy")
    assert users["web"].emitted() == "10001:10001" and users["db"].emitted() is None
    assert read_users(paths, "shop") == users
    assert "drops to postgres" in paths.log_file.read_text()


def test_check_refusals_stop_before_recording(paths, images, monkeypatch) -> None:
    _resolved(monkeypatch, SERVICES)
    monkeypatch.setattr(di.deploy_checks, "release_problems", lambda *a: (["no"], ["w"]))
    manifest = {**MANIFEST, "services": {**MANIFEST["services"], "db": DB_IMAGE}}
    with pytest.raises(DeployRefused, match="no"):
        di.prepare_release_users(paths, production_target(paths, "shop"), manifest,
                                 component="deploy")
    assert read_users(paths, "shop") == {}


def test_a_rollback_keeps_the_recorded_user_of_an_undeclared_service(
        paths, images, monkeypatch, capsys) -> None:
    _resolved(monkeypatch, SERVICES)
    write_users(paths, "shop", {"db": ServiceUser(None, "manifest")})
    users = di.prepare_release_users(paths, production_target(paths, "shop"), MANIFEST,
                                     component="rollback", rollback=True)
    assert users["db"] == ServiceUser(None, "manifest")
    assert "keeps its recorded user" in capsys.readouterr().out
    with pytest.raises(DeployRefused):
        di.prepare_release_users(paths, production_target(paths, "shop"), MANIFEST,
                                 component="deploy")


COMPOSE = "services:\n  web:\n    build: .\n  db:\n    image: postgres:16\n"


def test_a_refused_bundle_deploy_leaves_its_install_open_and_says_what_to_add(
        paths, images, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"compose.yml": COMPOSE, "Dockerfile": "FROM x\n"})
    with docker_off() as up:
        assert run_deploy("myapp", paths, ref=V1) == 1
    assert not up.called
    err = capsys.readouterr().err
    assert "registry image postgres:16" in err and "user: image" in err
    assert "schema_version: 2" in err
    assert load_txn(paths, "myapp") is not None
    fixed = yaml.safe_load(manifest_text())
    fixed["services"]["db"] = DB_IMAGE
    fixed["schema_version"] = 2
    place_bundle(paths, timestamp=V2, files={"compose.yml": COMPOSE, "Dockerfile": "FROM x\n",
                                             "manifest.yml": yaml.safe_dump(fixed)})
    with docker_off() as up:
        assert run_deploy("myapp", paths, ref=V2) == 0
    assert up.call_args.kwargs["build"] is False
    overlay = yaml.safe_load(paths.project_compose_override("myapp").read_text())
    assert overlay["services"]["web"]["user"] == "10001:10001"
    assert "user" not in overlay["services"]["db"]
    assert load_txn(paths, "myapp") is None


def test_a_refused_stage_starts_nothing_and_a_good_one_records_staging_users(
        paths, images, capsys) -> None:
    from boxmunge.commands.promote_cmd import run_promote
    from boxmunge.commands.stage_cmd import run_stage
    from tests.stage_helpers import staging_docker_off
    add_project("myapp", paths)
    nginx = yaml.safe_load(manifest_text())
    nginx["services"]["web"]["security"] = {"user": "image", "reason": "nginx master"}
    nginx["schema_version"] = 2
    place_bundle(paths, timestamp=V1, files={"manifest.yml": yaml.safe_dump(nginx)})
    place_bundle(paths, timestamp=V2, files={"compose.yml": COMPOSE, "Dockerfile": "FROM x\n"})
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths, ref=V1) == 0
        docker["up"].reset_mock()
        assert run_stage("myapp", paths, ref=V2) == 1
    assert not docker["up"].called
    assert "registry image postgres:16" in capsys.readouterr().err
    assert read_users(paths, "myapp", staging=True) == {}
    fixed = yaml.safe_load(manifest_text())
    fixed["services"]["db"], fixed["schema_version"] = DB_IMAGE, 2
    place_bundle(paths, timestamp="2026-10-16T110000000000", files={
        "compose.yml": COMPOSE, "Dockerfile": "FROM x\n", "manifest.yml": yaml.safe_dump(fixed)})
    with staging_docker_off() as docker:
        assert run_stage("myapp", paths, ref="2026-10-16T110000000000") == 0
    assert all(c.kwargs["build"] is False for c in docker["up"].call_args_list)
    staged = read_users(paths, "myapp", staging=True)
    assert staged["web"].emitted() == "10001:10001"
    from boxmunge.staged_release import STAGING_OVERLAY, slot_dir
    overlay = yaml.safe_load((slot_dir(paths, "myapp") / STAGING_OVERLAY).read_text())
    assert overlay["services"]["web"]["user"] == "10001:10001"
    with staging_docker_off():
        assert run_promote("myapp", paths) == 0
    assert read_users(paths, "myapp")["web"].emitted() == "10001:10001"
    assert read_users(paths, "myapp", staging=True) == {}
