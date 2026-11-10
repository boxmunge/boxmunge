"""L-01: a pause whose stop fails keeps its snapshot's pairing.

The snapshot is taken before the stop; it is paired with the deploy that
ends the pause only once the stop lands. A failed stop leaves the pause
incomplete, and the run of `pause` that finishes it used to take no
snapshot and pair nothing, so that deploy could not roll its data back.
The pause record now names the snapshot, and the finishing run pairs it
while Docker shows the backup service has not run since it was taken.
"""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from boxmunge import docker_containers
from boxmunge.backup import BackupKind
from boxmunge.commands import pause_cmd
from boxmunge.docker_containers import StartState
from boxmunge.docker_run import DockerError
from boxmunge.pause import pause_incomplete, read_paused_state
from boxmunge.pending_snapshot import pending
from tests.test_commands.test_pause_snapshot import BEFORE, live_v1  # noqa: F401

LATER = datetime.now(timezone.utc) + timedelta(hours=1)
_SECONDS = itertools.count(10)


def _backups(paths, *, service_running: bool):
    """backup_locked writing a snapshot of its kind under a new name each
    time, or failing as a dump in a stopped service does."""
    def backup_locked(project, paths_, kind=BackupKind.MANUAL, manifest=None, **_kw):
        if not service_running:
            print("ERROR: service web is not running")
            return 1
        name = f"{project}-2026-11-01T1000{next(_SECONDS)}-{kind.value}.tar.gz.age"
        bdir = paths_.project_backups(project)
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / name).write_text(kind.value)
        return 0
    return patch("boxmunge.commands.backup_cmd.backup_locked", backup_locked)


def _pause(paths, *, stop_fails: bool = False, service_running: bool = True) -> int:
    stop = DockerError("container web did not stop") if stop_fails else None
    with patch.object(pause_cmd, "caddy_reload"), \
            patch.object(pause_cmd, "compose_stop", side_effect=stop), \
            patch.object(pause_cmd, "hold_restart_policies"), \
            _backups(paths, service_running=service_running):
        return pause_cmd.run_pause("myapp", paths, yes=True)


def _web(monkeypatch, *, running: bool, started_at: datetime = BEFORE) -> None:
    monkeypatch.setattr(docker_containers, "start_states", lambda project: {
        "myapp-web-1": StartState(service="web", running=running, started_at=started_at)})


@pytest.fixture
def failed_stop(live_v1):  # noqa: F811
    """A pause whose snapshot was taken and whose stop then failed."""
    assert _pause(live_v1, stop_fails=True) == 1
    assert pause_incomplete("myapp", live_v1)
    assert pending(live_v1, "myapp") is None
    return live_v1, read_paused_state("myapp", live_v1)["snapshot"]["name"]


def test_the_pause_record_names_its_snapshot(failed_stop) -> None:
    paths, name = failed_stop
    assert name.endswith("-prepause.tar.gz.age")
    assert (paths.project_backups("myapp") / name).exists()


def test_finishing_the_pause_pairs_the_snapshot_it_began_with(
        failed_stop, monkeypatch, capsys) -> None:
    """The failed stop did stop web, and nothing started it since."""
    paths, name = failed_stop
    _web(monkeypatch, running=False)
    capsys.readouterr()
    assert _pause(paths, service_running=False) == 0
    assert not pause_incomplete("myapp", paths)
    kept = pending(paths, "myapp")
    assert (kept["name"], kept["taken_by"]) == (name, "pause")
    assert f"{name} is the pre-deploy snapshot of the deploy that ends this pause" \
        in capsys.readouterr().out


def test_a_service_still_running_gets_a_fresh_snapshot(failed_stop, monkeypatch) -> None:
    """web kept running (and writing) past the failed stop: the first
    snapshot no longer holds the data the pause stops, so a new one is
    taken and paired; the first stays in backups/."""
    paths, name = failed_stop
    _web(monkeypatch, running=True)
    assert _pause(paths) == 0
    kept = pending(paths, "myapp")
    assert kept["name"] != name and kept["name"].endswith("-prepause.tar.gz.age")
    assert (paths.project_backups("myapp") / name).exists()


def test_a_service_that_ran_since_is_not_paired(failed_stop, monkeypatch, capsys) -> None:
    """web was started and stopped again since the snapshot: its data may
    have changed, and nothing runs now to take a new one."""
    paths, name = failed_stop
    _web(monkeypatch, running=False, started_at=LATER)
    capsys.readouterr()
    assert _pause(paths, service_running=False) == 0
    assert pending(paths, "myapp") is None
    out = capsys.readouterr().out
    assert f"{name} taken when this pause began stays in backups/ for a manual restore" in out
    assert "has run since" in out
