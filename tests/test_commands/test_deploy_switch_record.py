"""The deploy state records a switch only once production changed (logic
review 2026-11-09, finding 05).

At every failure point of the start, `current_ref` names the release whose
containers run. A start refused or failed before `compose up` ran changed
no container: nothing is recorded, and the install stays open at
`switching` with its own options, so `status`, backups, smoke and the
rollback plan keep reading the release that runs.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.compose_guard import ComposeRefused
from boxmunge.docker_run import DockerError
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from boxmunge.state import read_state
from tests.bundle_helpers import manifest_text, place_bundle
from tests.txn_helpers import docker_off, fake_backups

V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"
REF1, REF2 = f"myapp-{V1}", f"myapp-{V2}"


def _prod_v1(paths) -> dict:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"manifest.yml": manifest_text(backup="postgres")})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
    place_bundle(paths, timestamp=V2, files={"manifest.yml": manifest_text(backup="postgres")})
    return read_state(paths.project_deploy_state("myapp"))


# Each patches one step of the start to fail before `compose up` runs.
BEFORE_UP = {
    "promote_candidates": lambda: patch("boxmunge.commands.deploy.promote_candidates",
                                        side_effect=DockerError("docker tag failed")),
    "prepare_storage": lambda: patch(
        "boxmunge.commands.deploy.deploy_storage.prepare_storage",
        side_effect=OSError(28, "No space left on device")),
    "start check": lambda: patch("boxmunge.compose_guard.check_start",
                                 side_effect=ComposeRefused("bind source changed kind")),
    "missing image": lambda: patch("boxmunge.docker_containers.absent_images",
                                   return_value=[("web", "nginx:1.27")]),
    "naming the running builds": lambda: patch(
        "boxmunge.compose_guard._name_running_builds",
        side_effect=DockerError("cannot read the overlay")),
}


@pytest.mark.parametrize("point", sorted(BEFORE_UP))
def test_a_start_that_never_ran_records_nothing_and_stays_open(
        paths, capsys, point) -> None:
    before = _prod_v1(paths)
    with docker_off() as up, fake_backups([]), BEFORE_UP[point]():
        assert run_deploy("myapp", paths, ref=V2) == 1
        up.assert_not_called()
    after = read_state(paths.project_deploy_state("myapp"))
    assert after["current_ref"] == REF1
    assert after["history"] == before["history"]
    assert after["last_started_at"] == before["last_started_at"]
    txn = load_txn(paths, "myapp")
    assert txn is not None and txn.phase == "switching" and txn.ref == REF2
    err = capsys.readouterr().err
    assert "did not start or change production's containers" in err
    assert f"prod-deploy myapp --ref {REF2}" in err and "rollback myapp" in err


def test_the_rerun_finishes_it_once_the_cause_is_fixed(paths) -> None:
    _prod_v1(paths)
    with docker_off(), fake_backups([]), BEFORE_UP["start check"]():
        assert run_deploy("myapp", paths, ref=V2) == 1
    with docker_off():
        assert run_deploy("myapp", paths) == 0
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == REF2 and state["history"][0]["ref"] == REF1
    assert load_txn(paths, "myapp") is None


@pytest.mark.parametrize("point", ["compose up", "smoke"])
def test_once_up_ran_the_switch_is_recorded(paths, point) -> None:
    """From `compose up` on, production runs (or partly runs) the new
    release: it is recorded, with the release it replaced to roll back to."""
    _prod_v1(paths)
    failing = (patch("boxmunge.compose_guard.compose_up",
                     side_effect=DockerError("container web exited (1)"))
               if point == "compose up" else
               patch("boxmunge.commands.deploy.smoke_ok", return_value=False))
    with docker_off(), fake_backups([]), failing:
        assert run_deploy("myapp", paths, ref=V2) == 1
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == REF2 and state["history"][0]["ref"] == REF1
    assert load_txn(paths, "myapp") is None


def test_a_first_deploy_never_started_stays_a_first_deploy(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off(), BEFORE_UP["start check"]():
        assert run_deploy("myapp", paths, ref=V1) == 1
    assert "current_ref" not in read_state(paths.project_deploy_state("myapp"))
    assert load_txn(paths, "myapp").phase == "switching"
    with docker_off():
        assert run_deploy("myapp", paths) == 0
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == REF1


def test_a_rollback_that_never_started_stays_open(paths, capsys) -> None:
    """Rolling back a deploy that ran: the old release's start is refused
    before `compose up`, so production still runs v2 and says so."""
    from boxmunge.commands.rollback import run_rollback
    _prod_v1(paths)
    with docker_off(), fake_backups([]):
        assert run_deploy("myapp", paths, ref=V2) == 0
    restore = patch("boxmunge.commands.rollback.restore_locked",
                    lambda p, pa, snapshot, txn=None: 0)
    with docker_off() as up, restore, BEFORE_UP["start check"]():
        assert run_rollback("myapp", paths, yes=True) == 1
        up.assert_not_called()
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == REF2
    txn = load_txn(paths, "myapp")
    assert txn.source == "rollback" and txn.phase == "switching"
    assert "Rerun 'rollback myapp'" in capsys.readouterr().err
    with docker_off(), restore:
        assert run_rollback("myapp", paths, yes=True) == 0
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == REF1
