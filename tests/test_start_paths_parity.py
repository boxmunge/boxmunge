"""Every production start agrees on the users record (review 2026-11-09, 03).

`data chown` writes the users record. The overlay replays it only when it is
rendered, and a `docker start` runs a container as it was created. So every
start either renders the overlay first, or is a deploy that renders its
own, or is refused while the overlay or the containers it would start run
another user than the record says. Here the callers of compose_up_checked
and start_containers_checked are enumerated from the source, so a new one
has to be placed in one of those groups, and those that render nothing are
run against a record newer than the overlay.
"""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

import boxmunge
from boxmunge import compose_guard, docker_containers
from boxmunge.compose_guard import ComposeRefused, check_start
from boxmunge.overlay_users import stale_containers_problem, stale_overlay_problem
from boxmunge.paths import BoxPaths
from boxmunge.run_as import ServiceUser, write_users

NAME = "shop"
SRC = Path(boxmunge.__file__).parent
PROD = ["compose.yml", "compose.boxmunge.yml"]

# Who keeps the overlay in step with the record, for each start.
RENDERS = "renders the overlay from the record first"
DEPLOYS = "a deploy or stage: writes the overlay and the record together"
GUARDED = "renders nothing: refused while the overlay or containers are stale"
CALLERS = {
    ("commands/deploy.py", "_start_and_verify"): DEPLOYS,
    ("legacy_stage_ops.py", "finish_apply"): DEPLOYS,
    ("staging_bringup.py", "_prepare_storage"): DEPLOYS,
    ("staging_bringup.py", "bring_up_staging"): DEPLOYS,
    ("commands/resume_cmd.py", "resume_locked"): RENDERS,
    ("commands/recover_cmd.py", "recover_locked"): RENDERS,
    ("commands/upgrade_steps.py", "_restart_locked"): RENDERS,
    ("userns/bringup.py", "_project"): RENDERS,
    ("cve/quarantine.py", "lift_quarantine"): RENDERS,
    ("container_update.py", "_recreate"): GUARDED,
    ("commands/restore.py", "_up"): GUARDED,
    ("production_stopped.py", "start_stopped"): GUARDED,
    ("commands/data_cmd.py", "_start_again"): GUARDED,
}


def _callers() -> set[tuple[str, str]]:
    found = set()
    for path in SRC.rglob("*.py"):
        if path.name == "compose_guard.py":
            continue
        tree = ast.parse(path.read_text())
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) in (
                        "compose_up_checked", "start_containers_checked"):
                    found.add((str(path.relative_to(SRC)), fn.name))
    return found


def test_every_start_is_placed() -> None:
    assert _callers() == set(CALLERS), (
        "a start was added or moved: say in CALLERS how it keeps the overlay in step "
        "with the users record")


@pytest.fixture
def stale(paths: BoxPaths):
    """A record that says app runs as 10002 (data chown wrote it) over an
    overlay still rendered for 10001."""
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    (project_dir / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"app": {"image": "shop-app:1"}}}))
    paths.project_compose_override(NAME).write_text(yaml.safe_dump(
        {"services": {"app": {"user": "10001:10001"}, "db": {"read_only": True}}}))
    write_users(paths, NAME, {"app": ServiceUser("10002:10002", "data-chown", ""),
                              "db": ServiceUser(None, "image", "postgres")})
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.compose_guard.start_containers") as start, \
            patch("boxmunge.notify.send_notification", lambda *a, **k: True):
        yield paths, up, start


def test_a_record_newer_than_the_overlay_is_found(stale) -> None:
    paths, _up, _start = stale
    problem = stale_overlay_problem(paths, NAME)
    assert "app (the record says 10002:10002, the overlay 10001:10001)" in problem
    assert "db" not in problem
    assert f"prod-deploy {NAME}" in problem


def test_a_record_the_overlay_replays_is_not(stale) -> None:
    paths, _up, _start = stale
    paths.project_compose_override(NAME).write_text(yaml.safe_dump(
        {"services": {"app": {"user": "10002:10002"}}}))
    assert stale_overlay_problem(paths, NAME) is None


def test_only_a_user_boxmunge_sets_is_compared_with_a_container() -> None:
    paths = SimpleNamespace()
    with patch("boxmunge.overlay_users._record",
               lambda p, n: {"app": "10002:10002", "db": None}):
        assert stale_containers_problem(paths, NAME, {"app": "10002:10002",
                                                      "db": "postgres"}) is None
        assert "app (created as 10001:10001" in stale_containers_problem(
            paths, NAME, {"app": "10001:10001"})


@pytest.mark.parametrize("bypass", [{"deploying": True}, {"txn": "t1"}])
def test_a_deploy_or_an_install_core_is_not_held_to_the_old_overlay(stale, bypass) -> None:
    """They render the overlay themselves; the check goes on past it."""
    paths, _up, _start = stale
    with patch.object(compose_guard, "validate_release_tree",
                      side_effect=RuntimeError("past the users check")), \
            patch.object(compose_guard, "_refuse_if_install_open"):
        with pytest.raises(RuntimeError, match="past the users check"):
            check_start(paths, NAME, component="deploy", compose_files=PROD, **bypass)


def _container_update(paths) -> None:
    from boxmunge.container_update import _recreate
    _recreate(paths, SimpleNamespace(is_caddy=False, name=NAME, compose_files=PROD))


def _restore(paths) -> None:
    from boxmunge.commands.restore import _up
    _up(paths, NAME, PROD, canary=False)


def _staging_copy_restart(paths) -> None:
    from boxmunge.production_stopped import start_stopped
    with patch("boxmunge.production_stopped._all_present", lambda *a: False):
        start_stopped(paths, NAME, [f"{NAME}-app-1"], component="health", page=False)


@pytest.mark.parametrize("start", [_container_update, _restore, _staging_copy_restart])
def test_a_start_that_renders_nothing_is_refused_over_a_stale_overlay(stale, start) -> None:
    from boxmunge.production_stopped import ProductionDownError
    paths, up, _start = stale
    with pytest.raises((ComposeRefused, ProductionDownError),
                       match="the users record changed after it was generated"):
        start(paths)
    up.assert_not_called()


def test_a_docker_start_of_containers_created_as_the_old_user_is_refused(
        stale, monkeypatch) -> None:
    from boxmunge.compose_guard import start_containers_checked
    paths, _up, start = stale
    monkeypatch.setattr(docker_containers, "container_bind_sources", lambda p: [])
    monkeypatch.setattr(docker_containers, "container_users",
                        lambda p: {"app": "10001:10001", "db": "postgres"})
    monkeypatch.setattr("boxmunge.bind_sources.read_record", lambda p: {"sources": {}})
    monkeypatch.setattr("boxmunge.bind_sources.check_sources", lambda *a: None)
    with pytest.raises(ComposeRefused, match="created before the users record changed"):
        start_containers_checked(paths, NAME, [f"{NAME}-app-1"], component="data-adopt")
    start.assert_not_called()
