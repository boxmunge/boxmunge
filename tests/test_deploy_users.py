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
DB_IMAGE = {"security": {"user": "image", "reason": "drops to postgres"}}
V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"


@pytest.fixture
def images(monkeypatch):
    """No builds or pulls; every image sets no USER."""
    built: list[list[str]] = []
    monkeypatch.setattr(di, "build_and_pull",
                        lambda target, s, refetch=frozenset(): built.append(sorted(s)) or {})
    monkeypatch.setattr(di, "image_facts", lambda ref: ImageFacts("sha256:" + "a" * 64, "", ()))
    return built


def _resolved(monkeypatch, services, compose_users=None):
    monkeypatch.setattr(di, "resolved_services", lambda target: ({}, services))
    monkeypatch.setattr(di, "compose_users", lambda target: compose_users or {})


SERVICES = {"web": {"build": ".", "image": "boxmunge.invalid/shop/web"},
            "db": {"image": "postgres:16"}}


def test_every_root_registry_service_is_listed_and_nothing_recorded(
        paths, images, monkeypatch) -> None:
    _resolved(monkeypatch, {**SERVICES, "cache": {"image": "redis:7"}})
    with pytest.raises(DeployRefused) as e:
        di.prepare_release_users(paths, production_target(paths, "shop"), MANIFEST,
                                 component="deploy")
    assert len(e.value.problems) == 3  # cache and db, both named, and how to merge them
    assert "merge their blocks" in e.value.problems[-1]
    assert read_users(paths, "shop") == {}


def test_decisions_are_recorded_and_opt_outs_logged(paths, images, monkeypatch) -> None:
    _resolved(monkeypatch, SERVICES)
    manifest = {**MANIFEST, "services": {**MANIFEST["services"], "db": DB_IMAGE}}
    users = di.prepare_release_users(paths, production_target(paths, "shop"), manifest,
                                     component="deploy")
    assert users["web"].emitted() == "10001:10001" and users["db"].emitted() is None
    assert read_users(paths, "shop") == {}  # recorded only once the configs are written
    di.record_release_users(paths, production_target(paths, "shop"), manifest, users,
                            component="deploy")
    assert read_users(paths, "shop") == users
    assert "drops to postgres" in paths.log_file.read_text()


def test_the_overlays_own_user_is_not_taken_for_compose_ymls(paths, images, monkeypatch) -> None:
    """The resolved model carries the last decision through the overlay; a
    change of decision must not be read back as compose.yml's choice."""
    services = {"web": {**SERVICES["web"], "user": "0:0"}, "worker": {
        **SERVICES["web"], "user": "1000"}}
    _resolved(monkeypatch, services, compose_users={"worker": 1000})
    users = di.prepare_release_users(paths, production_target(paths, "shop"), MANIFEST,
                                     component="deploy")
    assert users["web"].source == "default" and users["worker"].source == "compose"


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
    assert not paths.project_compose_override("myapp").exists()  # decided from a scratch overlay
    assert not paths.project_caddy_site("myapp").exists()
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


def _declared(declare: bool) -> dict[str, str]:
    manifest = yaml.safe_load(manifest_text())
    manifest["schema_version"] = 2
    if declare:
        manifest["services"]["db"] = DB_IMAGE
    return {"compose.yml": COMPOSE, "Dockerfile": "FROM x\n",
            "manifest.yml": yaml.safe_dump(manifest)}


def test_a_refusal_after_a_good_deploy_changes_nothing_and_can_be_abandoned(
        paths, images, capsys) -> None:
    from boxmunge.commands.install_abandon import run_abandon
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files=_declared(True))
    place_bundle(paths, timestamp=V2, files=_declared(False))
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    overlay = paths.project_compose_override("myapp").read_bytes()
    site = paths.project_caddy_site("myapp").read_bytes()
    record = read_users(paths, "myapp")
    capsys.readouterr()
    with docker_off() as up:
        assert run_deploy("myapp", paths, ref=V2) == 1
    assert not up.called
    err = capsys.readouterr().err
    assert "stopped at installed" in err and "--abandon" in err
    assert "rerun 'prod-deploy" not in err
    assert paths.project_compose_override("myapp").read_bytes() == overlay
    assert paths.project_caddy_site("myapp").read_bytes() == site
    assert read_users(paths, "myapp") == record
    assert run_abandon("myapp", paths) == 0
    assert load_txn(paths, "myapp") is None


def test_configs_that_fail_leave_the_record_as_it_was(paths, images, monkeypatch) -> None:
    from boxmunge.commands import release_config
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files=_declared(True))
    def broken(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(release_config, "prepare_caddy_config", broken)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 1
    assert read_users(paths, "myapp") == {}


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


def test_a_rollback_of_an_undecided_project_stays_undecided(paths, images, monkeypatch) -> None:
    _resolved(monkeypatch, SERVICES)
    assert di.prepare_release_users(paths, production_target(paths, "shop"), MANIFEST,
                                    component="rollback", rollback=True) == {}
    assert images == [["db", "web"]]  # still built: the start does not build
    assert read_users(paths, "shop") == {}


def test_a_rollbacks_restore_runs_the_restored_releases_images(paths, monkeypatch) -> None:
    """The backup service the restore starts is the restored release's: its
    candidates are named before the restore, not at the switch."""
    from boxmunge.commands import rollback
    order: list[str] = []
    from boxmunge.commands.release_config import ReleaseDecision
    monkeypatch.setattr(rollback, "decide_release_users",
                        lambda *a: order.append("decide") or ReleaseDecision({}))
    monkeypatch.setattr(rollback, "promote_candidates", lambda *a: order.append("promote"))
    monkeypatch.setattr(rollback, "prepare_compose_override", lambda *a, **k: None)
    monkeypatch.setattr(rollback, "check_start", lambda *a, **k: None)
    monkeypatch.setattr(rollback, "_restore_data", lambda *a: order.append("restore") or True)

    class Txn:
        id = "t1"
    assert rollback.restore_rolled_back_data("shop", paths, MANIFEST, "snap", Txn())
    assert order == ["decide", "promote", "restore"]
