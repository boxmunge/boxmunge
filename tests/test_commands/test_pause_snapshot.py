"""`pause` snapshots the project before it stops it, for the deploy that
ends the pause (`resume --no-start`): that deploy's containers are stopped,
so its own pre-deploy dump has nothing to run in, and without the pause's
snapshot its rollback could not restore data.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from boxmunge import docker_containers
from boxmunge.commands import pause_cmd
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.pause_snapshot import NO_SNAPSHOT_COST
from boxmunge.commands.resume_cmd import run_resume
from boxmunge.docker_containers import StartState
from boxmunge.pause import is_paused
from boxmunge.pending_snapshot import pending
from boxmunge.project_registry import add_project
from boxmunge.state import read_state
from tests.bundle_helpers import manifest_text, place_bundle
from tests.test_commands.test_chown_then_deploy import _backups
from tests.txn_helpers import docker_off

V1, V2 = "2026-10-13T090000000000", "2026-10-13T100000000000"
MANIFEST = manifest_text(backup="postgres")
BEFORE = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def live_v1(paths, fake_containers):
    """V1 deployed and running: web is the backup service."""
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"manifest.yml": MANIFEST})
    with docker_off(), _backups(paths, service_running=True):
        assert run_deploy("myapp", paths) == 0
    fake_containers.run("myapp", "web", "sha256:v1")
    return paths


@contextmanager
def _pause_docker():
    with patch.object(pause_cmd, "caddy_reload"), patch.object(pause_cmd, "compose_stop"), \
            patch.object(pause_cmd, "hold_restart_policies"):
        yield


def _pause(paths, *, service_running: bool = True, **kw) -> int:
    with _pause_docker(), _backups(paths, service_running=service_running):
        return pause_cmd.run_pause("myapp", paths, yes=True, **kw)


def _handover_deploy(paths, monkeypatch) -> None:
    """--no-start, then a deploy of V2 while web stays stopped."""
    assert run_resume("myapp", paths, no_start=True) == 0
    monkeypatch.setattr(docker_containers, "start_states", lambda project: {
        "myapp-web-1": StartState(service="web", running=False, started_at=BEFORE)})
    place_bundle(paths, timestamp=V2, files={"manifest.yml": MANIFEST})
    with docker_off(), _backups(paths, service_running=False):
        assert run_deploy("myapp", paths) == 0
    assert not is_paused("myapp", paths)


def test_the_deploy_that_ends_the_pause_pairs_with_its_snapshot(
        live_v1, monkeypatch, capsys) -> None:
    paths = live_v1
    assert _pause(paths) == 0
    taken = pending(paths, "myapp")
    assert taken["taken_by"] == "pause" and taken["name"].endswith("-prepause.tar.gz.age")
    assert taken["containers"] == ["myapp-web-1"]
    capsys.readouterr()
    _handover_deploy(paths, monkeypatch)
    out = capsys.readouterr().out
    assert f"Using the snapshot pause took before it stopped web" in out
    assert "Pre-deploy backup failed" not in out
    state = read_state(paths.project_deploy_state("myapp"))
    # The rollback to V1 restores the data as V1 left it: the pause's snapshot.
    assert state["history"][0]["ref"] == f"myapp-{V1}"
    assert state["pre_deploy_snapshot"] == taken["name"]


def test_a_failed_snapshot_refuses_the_pause(live_v1, capsys) -> None:
    paths = live_v1
    assert _pause(paths, service_running=False) == 1
    assert not is_paused("myapp", paths)
    err = capsys.readouterr().err
    assert "--no-snapshot" in err and NO_SNAPSHOT_COST in err


def test_no_snapshot_pauses_without_one_and_says_what_it_gives_up(
        live_v1, monkeypatch, capsys) -> None:
    paths = live_v1
    assert _pause(paths, service_running=False, no_snapshot=True) == 0
    assert is_paused("myapp", paths) and pending(paths, "myapp") is None
    assert NO_SNAPSHOT_COST in capsys.readouterr().out
    _handover_deploy(paths, monkeypatch)
    captured = capsys.readouterr()
    # One clear line, not the backup's refusal and the deploy's warning.
    assert "No pre-deploy snapshot: myapp is paused" in captured.out
    assert "Pre-deploy backup failed" not in captured.out
    assert "ERROR" not in captured.err


def test_a_failed_handover_deploy_rolls_back_to_the_paused_data(
        live_v1, monkeypatch, capsys) -> None:
    """pause, --no-start, a deploy of V2 whose start fails part-way (the
    pause stays; V2 is recorded, paired with the pause's snapshot), then
    rollback: V1 comes back with the data the pause's snapshot saved, and
    its start ends the pause."""
    from boxmunge.commands.rollback import run_rollback
    from boxmunge.docker_run import DockerError
    from boxmunge.pause import awaiting_deploy
    paths = live_v1
    assert _pause(paths) == 0
    taken = pending(paths, "myapp")["name"]
    assert run_resume("myapp", paths, no_start=True) == 0
    monkeypatch.setattr(docker_containers, "start_states", lambda project: {
        "myapp-web-1": StartState(service="web", running=False, started_at=BEFORE)})
    place_bundle(paths, timestamp=V2, files={"manifest.yml": MANIFEST})
    with docker_off() as up, _backups(paths, service_running=False), \
            patch("boxmunge.pause.compose_stop"):
        up.side_effect = DockerError("container web exited (1)")
        assert run_deploy("myapp", paths) == 1
    assert awaiting_deploy("myapp", paths)
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == f"myapp-{V2}" and state["pre_deploy_snapshot"] == taken
    assert "rollback myapp" in capsys.readouterr().err
    restored: list[str] = []
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked",
                             lambda p, pa, snapshot, txn=None: restored.append(snapshot) or 0):
        assert run_rollback("myapp", paths, yes=True) == 0
    assert restored == [taken]
    assert not is_paused("myapp", paths)
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V1}"


def test_a_rollbacks_restore_on_a_paused_project_leaves_it_stopped(live_v1) -> None:
    """The restore inside the rollback's install runs on the handed-over
    pause and starts nothing; the rollback's own start ends the pause."""
    from boxmunge.commands import restore
    from boxmunge.pause import mark_awaiting_deploy
    from boxmunge.release_txn import open_txn
    paths = live_v1
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("key")
    assert _pause(paths) == 0
    mark_awaiting_deploy("myapp", paths)
    snapshot = pending(paths, "myapp")["name"]
    txn = open_txn(paths, "myapp", source="rollback", ref=f"myapp-{V1}",
                   replaced_ref=f"myapp-{V2}", staged_id=None, snapshot=snapshot).id
    with patch.object(restore, "_run_restore_inner", return_value=0) as inner:
        assert restore.restore_locked("myapp", paths, snapshot=snapshot, txn=txn) == 0
        assert restore.restore_locked("myapp", paths, snapshot=snapshot) == 1   # not alone
    [call] = inner.call_args_list
    assert call.args[6] is True   # leave_stopped


@pytest.mark.parametrize("state", ["quarantined", "monitor-stopped"])
def test_nothing_running_to_dump_pauses_without_a_snapshot(live_v1, capsys, state) -> None:
    from boxmunge.state import write_state
    from tests.test_commands.cve_helpers import seed_quarantine
    paths = live_v1
    if state == "quarantined":
        seed_quarantine(paths, "myapp")
    else:
        write_state(paths.project_health_state("myapp"), {
            "status": "critical_stopped",
            "stopped_at": datetime.now(timezone.utc).isoformat()})
    assert _pause(paths, service_running=False) == 0
    assert is_paused("myapp", paths) and pending(paths, "myapp") is None
    assert "nothing runs to dump" in capsys.readouterr().out


@pytest.mark.parametrize("case, line", [
    ("default", "A data snapshot is taken first, for the deploy that ends the pause to roll "
                "back to (--no-snapshot skips it, e.g. in an emergency)"),
    ("no-snapshot", f"No snapshot (--no-snapshot): {NO_SNAPSHOT_COST}"),
    ("quarantined", "No snapshot: myapp is CVE-quarantined, so nothing runs to dump"),
])
def test_the_confirmation_says_what_happens_to_the_snapshot(live_v1, capsys, case, line) -> None:
    from tests.test_commands.cve_helpers import seed_quarantine
    paths = live_v1
    if case == "quarantined":
        seed_quarantine(paths, "myapp")
    with patch.object(pause_cmd, "confirm", return_value=False) as asked:
        assert pause_cmd.run_pause("myapp", paths, no_snapshot=case == "no-snapshot") == 1
    asked.assert_called_once_with("pause")
    assert f"  - {line}" in capsys.readouterr().out
    assert not is_paused("myapp", paths)


def test_the_deploy_shell_passes_no_snapshot_and_yes() -> None:
    from boxmunge.shell import operator_only_reason, run_command
    args = ["myapp", "--no-snapshot", "--yes"]
    assert operator_only_reason("pause", args) is None
    with patch("boxmunge.shell.subprocess.run") as run:
        run.return_value.returncode = 0
        run_command("pause", args)
    run.assert_called_once_with(["boxmunge-server", "pause", *args])


def test_a_pause_after_data_chown_keeps_the_chown_s_pairing(
        live_v1, monkeypatch, capsys) -> None:
    """Review of #144 (P3-1): data chown stopped the backup service after its
    snapshot; the pause tried to dump in it, failed, and refused naming the
    cost of --no-snapshot. The chown's snapshot is the data before either."""
    from boxmunge.pending_snapshot import record_pending
    paths = live_v1
    bdir = paths.project_backups("myapp")
    bdir.mkdir(parents=True, exist_ok=True)
    (bdir / "myapp-2026-11-01T100000-prechown.tar.gz.age").write_text("prechown")
    record_pending(paths, "myapp", "myapp-2026-11-01T100000-prechown.tar.gz.age",
                   "data chown", "web", ["myapp-web-1"])
    monkeypatch.setattr(docker_containers, "start_states", lambda project: {
        "myapp-web-1": StartState(service="web", running=False, started_at=BEFORE)})
    capsys.readouterr()
    assert _pause(paths, service_running=False) == 0
    out = capsys.readouterr().out
    assert "that data chown took" in out and "No new one is taken" in out
    assert NO_SNAPSHOT_COST not in out
    kept = pending(paths, "myapp")
    assert (kept["name"], kept["taken_by"]) == (
        "myapp-2026-11-01T100000-prechown.tar.gz.age", "data chown")
