"""data chown, then deploy: the deploy's rollback target pairs with the
snapshot data chown took before it stopped the service.

The deploy's own dump runs in the backup service, which data chown may
have stopped; it used to fail there, the deploy went on with a warning,
and its rollback could not restore the data. The snapshot is used only
while Docker shows the service has not run since; otherwise the deploy
pairs a stale snapshot and its rollback loses the writes made since.
"""
from __future__ import annotations

import itertools
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from boxmunge import chown_hold, docker_containers
from boxmunge.backup import BackupKind
from boxmunge.commands.backup_cmd import BackupResult
from boxmunge.commands import chown_snapshot, data_cmd
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.deploy_steps import take_pre_deploy_snapshot
from boxmunge.commands.rollback import find_rollback_target, run_rollback
from boxmunge.docker_containers import StartState
from boxmunge.docker_run import DockerError
from boxmunge.pending_snapshot import pending, record_pending
from boxmunge.project_registry import add_project
from boxmunge.state import read_state, write_state

from tests.bundle_helpers import manifest_text, place_bundle

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"
MANIFEST = manifest_text(backup="postgres")
BEFORE = datetime(2026, 1, 1, tzinfo=timezone.utc)


@contextmanager
def _docker():
    with patch("boxmunge.compose_guard.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        yield


def _backups(paths, *, service_running: bool):
    """The backup core writing a snapshot of its kind, or failing as a dump in
    a stopped service does."""
    seconds = itertools.count(10)

    def snapshot_locked(project, paths_, kind=BackupKind.MANUAL, manifest=None, **_kw):
        if not service_running:
            print("ERROR: service web is not running")
            return BackupResult(1, cause="service web is not running")
        name = f"{project}-2026-11-01T1000{next(seconds)}-{kind.value}.tar.gz.age"
        bdir = paths_.project_backups(project)
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / name).write_text(kind.value)
        return BackupResult(0, snapshot=bdir / name)
    return patch("boxmunge.commands.backup_cmd.snapshot_locked", snapshot_locked)


def _containers(monkeypatch, **states: StartState) -> None:
    """What Docker reports for the project's containers at use time."""
    monkeypatch.setattr(docker_containers, "start_states", lambda project: dict(states))


def _stopped(started_at=BEFORE) -> StartState:
    return StartState(service="web", running=False, started_at=started_at)


def _deploy(paths, ts) -> None:
    place_bundle(paths, timestamp=ts, files={"manifest.yml": MANIFEST, "VERSION": f"{ts}\n"})
    with _docker():
        assert run_deploy("myapp", paths) == 0


def _chowned(paths, monkeypatch) -> str:
    """V1 deployed, then web (the backup service) chowned; the name of the
    snapshot data chown kept for the next deploy."""
    add_project("myapp", paths)
    with _backups(paths, service_running=True):
        _deploy(paths, V1)
    pdir = paths.project_dir("myapp")
    (pdir / "uploads").mkdir(exist_ok=True)
    services = {"web": {"volumes": [
        {"type": "bind", "source": str(pdir / "uploads"), "target": "/u"}]}}
    monkeypatch.setattr(data_cmd, "resolved_services", lambda target: ({}, services))
    monkeypatch.setattr(data_cmd, "_running", lambda p, s: ["myapp-web-1"])
    monkeypatch.setattr(data_cmd, "_run", lambda cmd, **kw: None)
    monkeypatch.setattr(data_cmd, "chown_under", lambda *a: None)
    monkeypatch.setattr(data_cmd, "_containers", lambda p, s: ["myapp-web-1"])
    monkeypatch.setattr(data_cmd, "staging_copies", lambda *a: [])
    monkeypatch.setattr(chown_hold, "hold", lambda *a: [])
    monkeypatch.setattr(chown_snapshot, "running_by_service", lambda p: {"web": ["myapp-web-1"]})
    with _backups(paths, service_running=True):
        data_cmd.chown_locked(paths, "myapp", "web", (10001, 10001))
    return pending(paths, "myapp")["name"]


def test_the_deploy_uses_the_chown_snapshot_and_its_rollback_restores_it(
        paths, monkeypatch, capsys) -> None:
    taken = _chowned(paths, monkeypatch)
    assert taken.endswith("-prechown.tar.gz.age")
    _containers(monkeypatch, **{"myapp-web-1": _stopped()})
    capsys.readouterr()
    # data chown left the service stopped: a dump now would fail.
    with _backups(paths, service_running=False):
        _deploy(paths, V2)
    out = capsys.readouterr().out
    assert "Pre-deploy backup failed" not in out
    assert "Using the snapshot data chown took before it stopped web (" in out
    assert " ago; it has not run since) as the pre-deploy snapshot: " + taken in out
    assert "pending_snapshot" not in read_state(paths.project_deploy_state("myapp"))

    assert find_rollback_target(paths, "myapp").snapshot == taken
    restored = {}

    def fake_restore(project_name, paths_, snapshot=None, txn=None):
        restored["snapshot"] = snapshot
        return 0
    with patch("boxmunge.commands.rollback.restore_locked", fake_restore), _docker():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert restored == {"snapshot": taken}


@pytest.mark.parametrize("states, why", [
    ({"myapp-web-1": _stopped(BEFORE.replace(year=2099))}, "web has run since"),
    ({"myapp-web-1": StartState("web", True, BEFORE)}, "web is running again"),
    ({}, "myapp-web-1 of web no longer exists"),
], ids=["started-since", "running", "removed"])
def test_a_snapshot_the_service_has_run_past_is_dropped(
        paths, monkeypatch, capsys, states, why) -> None:
    """A start boxmunge did not make (a restart policy after a reboot, a
    plain docker start), a recreate or a removal: the deploy takes its own
    snapshot, or warns as it always did when it cannot."""
    _chowned(paths, monkeypatch)
    _containers(monkeypatch, **states)
    capsys.readouterr()
    with _backups(paths, service_running=True):
        _deploy(paths, V2)
    out = capsys.readouterr().out
    assert f"is not used, and is dropped: {why}" in out
    assert find_rollback_target(paths, "myapp").snapshot.endswith("-predeploy.tar.gz.age")


def test_a_snapshot_whose_service_ran_and_stopped_again_is_not_paired(
        paths, monkeypatch, capsys) -> None:
    """chown, docker start, a write, stop, deploy: pairing the snapshot would
    make the rollback drop that write; the deploy warns as it does for any
    failed pre-deploy backup, and rollback refuses."""
    _chowned(paths, monkeypatch)
    _containers(monkeypatch, **{"myapp-web-1": _stopped(datetime.now(timezone.utc)
                                                        + timedelta(minutes=1))})
    with _backups(paths, service_running=False):
        _deploy(paths, V2)
    assert "Pre-deploy backup failed" in capsys.readouterr().out
    assert run_rollback("myapp", paths, yes=True) == 1
    assert "no pre-deploy data snapshot" in capsys.readouterr().err


def test_when_docker_cannot_be_asked_it_is_not_used_but_kept(paths, monkeypatch, capsys) -> None:
    _chowned(paths, monkeypatch)

    def no_docker(project):
        raise DockerError("Cannot connect to the Docker daemon")
    monkeypatch.setattr(docker_containers, "start_states", no_docker)
    capsys.readouterr()
    with _backups(paths, service_running=True):
        name = take_pre_deploy_snapshot("myapp", paths, {"backup": {"type": "postgres"}}, False)
    assert name.endswith("-predeploy.tar.gz.age")
    assert "cannot be told (Cannot connect" in capsys.readouterr().out
    assert pending(paths, "myapp") is not None


def test_a_snapshot_of_another_release_is_not_used(paths, monkeypatch, capsys) -> None:
    add_project("myapp", paths)
    with _backups(paths, service_running=True):
        _deploy(paths, V1)
        record_pending(paths, "myapp", "myapp-2026-11-01T100000-prechown.tar.gz.age",
                       "data chown", "web", ["myapp-web-1"])
        state = read_state(paths.project_deploy_state("myapp"))
        state["pending_snapshot"]["ref"] = "myapp-older"
        write_state(paths.project_deploy_state("myapp"), state)
        name = take_pre_deploy_snapshot("myapp", paths, {"backup": {"type": "postgres"}}, False)
    assert name.endswith("-predeploy.tar.gz.age")
    assert "not of the live" in capsys.readouterr().out
    assert pending(paths, "myapp") is None


def test_a_backup_that_writes_nothing_is_no_snapshot(paths, capsys) -> None:
    """A quarantined project's backup skips with rc 0: the newest older
    snapshot must not pass for this deploy's."""
    add_project("myapp", paths)
    bdir = paths.project_backups("myapp")
    bdir.mkdir(parents=True)
    (bdir / "myapp-2026-01-01T020000-nightly.tar.gz.age").write_text("old")
    with patch("boxmunge.commands.backup_cmd.snapshot_locked", return_value=BackupResult(0)):
        assert take_pre_deploy_snapshot(
            "myapp", paths, {"backup": {"type": "postgres"}}, False) is None
    assert "wrote no pre-deploy snapshot" in capsys.readouterr().out
