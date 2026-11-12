# SPDX-License-Identifier: Apache-2.0
"""The readiness rules (boxmunge.readiness): one test per rule id, and the
review's input classes (Docker unreachable, a project mid-deploy).

The read-only and no-stall guarantees are in test_readiness_safety.py."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.docker_run import DockerError
from boxmunge.readiness import evaluate
from boxmunge.readiness_contract import parse, to_json
from boxmunge.version import write_installed_version
from tests.readiness_helpers import (
    COMMAND, IMAGE, Recorder, add_project, findings, ids, make_box, open_install,
)


@pytest.fixture
def recorder(monkeypatch) -> Recorder:
    rec = Recorder()
    monkeypatch.setattr("boxmunge.docker_run.subprocess.run", rec)
    return rec


@pytest.fixture
def box(tmp_path: Path, recorder):
    return make_box(tmp_path / "bm")


def _only(r, rule: str):
    [finding] = [f for f in findings(r) if f.id == rule]
    assert finding.when == "before"
    assert COMMAND.search(finding.remedy), finding.remedy
    return finding


def test_a_clean_box_passes(box) -> None:
    add_project(box, "alpha")
    r = evaluate(box)
    assert r.result == "pass" and ids(r) == []
    assert [p.name for p in r.projects] == ["alpha"] and r.installed == "0.11.7"
    assert parse(to_json(r)) == r


def test_a_pre_registered_project_is_not_listed(box) -> None:
    add_project(box, "alpha")
    box.project_dir("secrets-only").mkdir()
    assert [p.name for p in evaluate(box).projects] == ["alpha"]


# --- box rules --------------------------------------------------------------

def test_box_upgrade_floor(box) -> None:
    write_installed_version(box, "0.10.4", "abc1234")
    r = evaluate(box)
    finding = _only(r, "box.upgrade_floor")
    assert finding.severity == "block" and r.result == "blocked"
    assert "0.10.4" in finding.message and "`upgrade --target 0.11.6`" in finding.remedy
    assert "blocklist" not in finding.message  # the check leaves no blocklist entry
    assert r.installed == "0.10.4"


def test_box_upgrade_floor_without_a_version_record(box) -> None:
    box.version_file.unlink()
    r = evaluate(box)
    finding = _only(r, "box.upgrade_floor")
    assert str(box.version_file) in finding.remedy
    assert r.installed == "0.0.0" and r.result == "blocked"


def test_box_compose_version(box, recorder) -> None:
    recorder.compose_version = "2.30.0"
    finding = _only(evaluate(box), "box.compose_version")
    assert finding.severity == "block" and "2.30.0" in finding.message
    assert "apt-get install --only-upgrade docker-compose-plugin" in finding.remedy


def test_box_dry_run(box) -> None:
    """Whatever fails `upgrade --dry-run` blocks: the check is never laxer."""
    add_project(box, "alpha")
    box.project_users_record("alpha").write_text("not json\n")
    assert run_upgrade(box, dry_run=True) == 1
    r = evaluate(box)
    finding = _only(r, "box.dry_run")
    assert finding.severity == "block" and "cannot read the users record" in finding.message


def test_box_docker(box, monkeypatch) -> None:
    add_project(box, "alpha")

    def unreachable(ref):
        raise DockerError("Cannot connect to the Docker daemon")
    monkeypatch.setattr("boxmunge.docker_containers.local_image", unreachable)
    finding = _only(evaluate(box), "box.docker")
    assert finding.severity == "block" and "Cannot connect" in finding.message


# --- project rules ----------------------------------------------------------

def test_project_validate(box) -> None:
    add_project(box, "shop", compose=f"services:\n  web:\n    image: {IMAGE}\n"
                                     f"    pull_policy: always\n")
    r = evaluate(box)
    finding = _only(r, "project.validate")
    assert finding.severity == "todo" and "pull_policy: always" in finding.message
    assert "`validate shop`" in finding.remedy and r.result == "pass"


def test_project_compose(box) -> None:
    add_project(box, "shop", compose=f"name: other\nservices:\n  web:\n    image: {IMAGE}\n")
    r = evaluate(box)
    finding = _only(r, "project.compose")
    assert finding.severity == "todo" and "top-level name" in finding.message
    assert "`prod-deploy shop`" in finding.remedy and r.result == "pass"


def test_project_left_as_is(box) -> None:
    add_project(box, "shop")
    open_install(box, "shop")
    r = evaluate(box)
    finding = _only(r, "project.left_as_is")
    assert finding.severity == "todo" and "an install (shop-x" in finding.message
    assert "prod-deploy shop" in finding.remedy and ids(r) == [("shop", "project.left_as_is")]


def test_project_unreadable_manifest(box) -> None:
    add_project(box, "shop")
    box.project_manifest("shop").write_text("- not\n- a mapping\n")
    add_project(box, "alpha", compose=f"name: other\nservices:\n  web:\n    image: {IMAGE}\n")
    r = evaluate(box)
    finding = _only(r, "project.unreadable")
    assert finding.severity == "block" and "not a YAML mapping" in finding.message
    assert "`prod-deploy shop --redeploy`" in finding.remedy
    assert "`project-delete shop`" in finding.remedy
    # The dry run still reports every other project.
    assert ids(r) == [("alpha", "project.compose"), ("shop", "project.unreadable")]


@pytest.mark.skipif(os.geteuid() == 0, reason="root enters any directory")
def test_a_project_directory_the_check_cannot_enter_is_unreadable(box) -> None:
    """The dry run passes over it (lexists is False on EACCES); the upgrade,
    as root, reads it. So the check, as deploy, must not pass it."""
    add_project(box, "alpha")
    pdir = add_project(box, "shop")
    pdir.chmod(0o000)
    try:
        r = evaluate(box)
    finally:
        pdir.chmod(0o755)
    finding = _only(r, "project.unreadable")
    assert ids(r) == [("shop", "project.unreadable")] and r.result == "blocked"
    assert f"`sudo chown -R deploy:deploy {pdir}`" in finding.remedy


def test_project_unreadable_compose_model(box) -> None:
    add_project(box, "shop", compose="services: [\n")
    r = evaluate(box)
    finding = _only(r, "project.unreadable")
    assert "cannot be resolved" in finding.message and r.result == "blocked"


def test_project_image_missing(box, fake_containers) -> None:
    add_project(box, "shop")
    fake_containers.images[IMAGE] = None
    r = evaluate(box)
    finding = _only(r, "project.image_missing")
    assert finding.severity == "block" and IMAGE in finding.message
    assert "`prod-deploy shop --redeploy`" in finding.remedy
    assert r.projects[0].result == "blocked"


# --- review focus -----------------------------------------------------------

def test_docker_unreachable_is_one_box_block(box, monkeypatch) -> None:
    """Review focus 1: not one misleading image_missing per project."""
    for name in ("alpha", "beta", "gamma"):
        add_project(box, name)
    asked = []

    def unreachable(ref):
        asked.append(ref)
        raise DockerError("Cannot connect to the Docker daemon")
    monkeypatch.setattr("boxmunge.docker_containers.local_image", unreachable)
    r = evaluate(box)
    assert ids(r) == [(None, "box.docker")] and r.result == "blocked"
    assert len(asked) == 1  # the image checks stop at the first failure


def test_open_install_is_left_as_is_and_takes_no_lock(box, monkeypatch) -> None:
    """Review focus 2: a project mid-deploy is reported, not locked or read."""
    add_project(box, "shop")
    open_install(box, "shop")
    taken = []
    monkeypatch.setattr("boxmunge.fileutil.fcntl.flock",
                        lambda fd, op: taken.append(op))
    monkeypatch.setattr("boxmunge.readiness.gather_validation",
                        lambda name, paths: pytest.fail(f"validated {name} mid-deploy"))
    before = sorted(p.name for p in box.state.iterdir())
    r = evaluate(box)
    assert ids(r) == [("shop", "project.left_as_is")]
    assert taken == [] and not box.project_lock_file("shop").exists()
    assert sorted(p.name for p in box.state.iterdir()) == before


def test_never_laxer_than_the_dry_run(box) -> None:
    """Every box below fails `upgrade --dry-run`; each is blocked."""
    add_project(box, "alpha")
    box.project_manifest("alpha").write_text("services: [\n")
    assert run_upgrade(box, dry_run=True) == 1
    assert evaluate(box).result == "blocked"


# --- a check that fails is a block, never a missing verdict -------------------

def _manifest_with(paths, name: str, **values) -> None:
    import yaml
    path = paths.project_manifest(name)
    path.write_text(yaml.dump({**yaml.safe_load(path.read_text()), **values}))


@pytest.mark.parametrize("env_files, error", [(5, "TypeError"), ([5], "TypeError")])
def test_a_project_check_that_fails_is_unreadable_naming_it(box, env_files, error) -> None:
    add_project(box, "alpha")
    add_project(box, "shop")
    _manifest_with(box, "shop", env_files=env_files)
    r = evaluate(box)
    finding = _only(r, "project.unreadable")
    assert finding.message.startswith(f"project shop could not be checked: {error}: ")
    assert ids(r) == [("shop", "project.unreadable")] and r.result == "blocked"


def test_a_box_rule_that_fails_is_a_block_naming_it(box, monkeypatch) -> None:
    def broken():
        raise RuntimeError("compose version probe broke")
    monkeypatch.setattr("boxmunge.readiness.compose_version_problem", broken)
    finding = _only(evaluate(box), "box.compose_version")
    assert finding.message == ("box.compose_version could not be checked: RuntimeError: "
                               "compose version probe broke")


def test_projects_that_cannot_be_listed_are_a_dry_run_block(box, monkeypatch) -> None:
    def broken(paths):
        raise PermissionError(13, "Permission denied", str(paths.projects))
    monkeypatch.setattr("boxmunge.readiness._unenterable", broken)
    r = evaluate(box)
    assert _only(r, "box.dry_run").message.startswith(
        "the projects could not be checked: PermissionError: ")
    assert r.projects == ()


def test_an_open_install_with_an_unreadable_pause_record_is_left_as_is(box) -> None:
    add_project(box, "shop")
    open_install(box, "shop")
    box.project_paused_state("shop").write_text("{not json")
    assert ids(evaluate(box)) == [("shop", "project.left_as_is")]
