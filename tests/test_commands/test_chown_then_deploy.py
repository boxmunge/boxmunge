"""data chown, then deploy: the deploy's rollback target pairs with the
snapshot data chown took before it stopped the service.

The deploy's own dump runs in the backup service, which data chown may
have stopped; it used to fail there, the deploy went on with a warning,
and its rollback could not restore the data.
"""
from __future__ import annotations

import itertools
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from boxmunge.backup import BackupKind
from boxmunge.commands import data_cmd
from boxmunge.compose_guard import (
    ComposeRefused, compose_up_checked, start_containers_checked,
)
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.deploy_steps import take_pre_deploy_snapshot
from boxmunge.commands.rollback import find_rollback_target, run_rollback
from boxmunge.pending_snapshot import pending, record_pending
from boxmunge.project_registry import add_project
from boxmunge.state import read_state, write_state

from tests.bundle_helpers import manifest_text, place_bundle

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"
MANIFEST = manifest_text(backup="postgres")


@contextmanager
def _docker():
    with patch("boxmunge.compose_guard.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        yield


def _backups(paths, *, service_running: bool):
    """backup_locked writing a snapshot of its kind, or failing as a dump in
    a stopped service does."""
    seconds = itertools.count(10)

    def backup_locked(project, paths_, kind=BackupKind.MANUAL, manifest=None, **_kw):
        if not service_running:
            print("ERROR: service web is not running")
            return 1
        name = f"{project}-2026-11-01T1000{next(seconds)}-{kind.value}.tar.gz.age"
        bdir = paths_.project_backups(project)
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / name).write_text(kind.value)
        return 0
    return patch("boxmunge.commands.backup_cmd.backup_locked", backup_locked)


def _deploy(paths, ts) -> None:
    place_bundle(paths, timestamp=ts, files={"manifest.yml": MANIFEST, "VERSION": f"{ts}\n"})
    with _docker():
        assert run_deploy("myapp", paths) == 0


def _chown(paths, monkeypatch) -> None:
    pdir = paths.project_dir("myapp")
    (pdir / "uploads").mkdir(exist_ok=True)
    services = {"web": {"volumes": [
        {"type": "bind", "source": str(pdir / "uploads"), "target": "/u"}]}}
    monkeypatch.setattr(data_cmd, "resolved_services", lambda target: ({}, services))
    monkeypatch.setattr(data_cmd, "_running", lambda p, s: ["myapp-web-1"])
    monkeypatch.setattr(data_cmd, "_run", lambda cmd, **kw: None)
    monkeypatch.setattr(data_cmd, "chown_under", lambda *a: None)
    with _backups(paths, service_running=True):
        data_cmd.chown_locked(paths, "myapp", "web", (10001, 10001))


def test_the_deploy_uses_the_chown_snapshot_and_its_rollback_restores_it(
        paths, monkeypatch, capsys) -> None:
    add_project("myapp", paths)
    with _backups(paths, service_running=True):
        _deploy(paths, V1)
    _chown(paths, monkeypatch)
    taken = pending(paths, "myapp")["name"]
    assert taken.endswith("-prechown.tar.gz.age")
    capsys.readouterr()
    # data chown left the service stopped: a dump now would fail.
    with _backups(paths, service_running=False):
        _deploy(paths, V2)
    out = capsys.readouterr().out
    assert "Pre-deploy backup failed" not in out
    assert "Using the snapshot data chown took before it changed the data" in out
    assert taken in out
    assert "pending_snapshot" not in read_state(paths.project_deploy_state("myapp"))

    assert find_rollback_target(paths, "myapp").snapshot == taken
    restored = {}

    def fake_restore(project_name, paths_, snapshot=None, txn=None):
        restored["snapshot"] = snapshot
        return 0
    with patch("boxmunge.commands.rollback.restore_locked", fake_restore), _docker():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert restored == {"snapshot": taken}


def test_a_snapshot_of_another_release_is_not_used(paths, capsys) -> None:
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


def test_a_backup_that_writes_nothing_is_no_snapshot(paths, capsys) -> None:
    """A quarantined project's backup skips with rc 0: the newest older
    snapshot must not pass for this deploy's."""
    add_project("myapp", paths)
    bdir = paths.project_backups("myapp")
    bdir.mkdir(parents=True)
    (bdir / "myapp-2026-01-01T020000-nightly.tar.gz.age").write_text("old")
    with patch("boxmunge.commands.backup_cmd.backup_locked", return_value=0):
        assert take_pre_deploy_snapshot(
            "myapp", paths, {"backup": {"type": "postgres"}}, False) is None
    assert "wrote no pre-deploy snapshot" in capsys.readouterr().out


PROD_FILES = ["compose.yml", "compose.boxmunge.yml"]


def _chowned(paths, monkeypatch) -> str:
    add_project("myapp", paths)
    with _backups(paths, service_running=True):
        _deploy(paths, V1)
    _chown(paths, monkeypatch)
    return pending(paths, "myapp")["name"]


def test_a_production_start_of_the_service_spends_it(paths, monkeypatch, capsys) -> None:
    """recover (or restore, resume, adopt) runs the service again: its data
    may change, so the next deploy dumps afresh rather than pairing its
    rollback with older data."""
    _chowned(paths, monkeypatch)
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, "myapp", component="recover", compose_files=PROD_FILES)
    assert pending(paths, "myapp") is None
    capsys.readouterr()
    with _backups(paths, service_running=True):
        _deploy(paths, V2)
    assert find_rollback_target(paths, "myapp").snapshot.endswith("-predeploy.tar.gz.age")


def test_starting_another_service_keeps_it(paths, monkeypatch) -> None:
    taken = _chowned(paths, monkeypatch)
    with patch("boxmunge.compose_guard.compose_up"):
        compose_up_checked(paths, "myapp", component="restore", compose_files=PROD_FILES,
                           services=["worker"])
    with patch("boxmunge.compose_guard.start_containers"):
        start_containers_checked(paths, "myapp", ["myapp-worker-1"], component="data-adopt")
    assert pending(paths, "myapp")["name"] == taken


def test_a_docker_start_of_its_containers_spends_it(paths, monkeypatch) -> None:
    _chowned(paths, monkeypatch)
    with patch("boxmunge.compose_guard.start_containers") as start:
        start_containers_checked(paths, "myapp", ["myapp-web-1"], component="stage")
    start.assert_called_once()
    assert pending(paths, "myapp") is None



def test_an_unreadable_deploy_state_refuses_a_docker_start(paths, monkeypatch) -> None:
    _chowned(paths, monkeypatch)
    paths.project_deploy_state("myapp").write_text("{not json")
    with patch("boxmunge.compose_guard.start_containers") as start, \
            pytest.raises(ComposeRefused, match="deploy state cannot be read"):
        start_containers_checked(paths, "myapp", ["myapp-web-1"], component="data-adopt")
    start.assert_not_called()
