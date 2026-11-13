"""A stored snapshot is never replaced, and take_snapshot names the one it wrote.

Snapshot names carried a timestamp to the second, and the encrypted file
was published with a replacing rename: two backups of one kind in the same
second, or one after the clock stepped back onto an old name, overwrote a
stored snapshot (a paired one too: retention spares its name, not its
contents). take_snapshot then found no new name and returned (0, None).

These run the real core and the real publication. Only the dump and age
are stood in for (age copies its input, so each file shows whose data it
holds).
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import backup
from boxmunge.backup import BackupKind, parse_snapshot
from boxmunge.commands import backup_cmd
from boxmunge.commands.backup_cmd import list_snapshots, take_snapshot
from boxmunge.snapshot_pairings import paired_snapshots
from boxmunge.state import write_state
from tests.fake_system_container import host_path

P = "demo"
MANIFEST = {"project": P, "services": {"db": {}},
            "backup": {"type": "postgres", "dump_command": "dump.sh"}}
STEPPED_BACK = datetime(2026, 6, 1, tzinfo=timezone.utc)


@pytest.fixture
def project(paths, system_container) -> Path:
    """A project whose dumps hold the payload the test names; age copies."""
    def copying_age(cmd: list[str]) -> subprocess.CompletedProcess:
        if "-o" in cmd:
            host_path(paths, cmd[cmd.index("-o") + 1]).write_bytes(
                host_path(paths, cmd[-1]).read_bytes())
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    system_container.handler = copying_age
    bdir = paths.project_backups(P)
    bdir.mkdir(parents=True)
    paths.project_manifest(P).write_text("project: demo\n")   # deployed, not pre-registered
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("# public key: age1test\nAGE-SECRET-KEY-1TEST\n")
    return bdir


def _snapshot(paths, payload: bytes, kind=BackupKind.PREDEPLOY,
              manifest=MANIFEST) -> tuple[int, str | None]:
    def dump(paths_, project, *a, **k) -> Path:
        raw = paths_.project_backups(project) / ".dump-test"
        raw.write_bytes(payload)
        return raw

    with patch.object(backup_cmd, "execute_dump", dump):
        return take_snapshot(P, paths, kind, manifest)


def _leftovers(bdir: Path) -> list[str]:
    return sorted(f.name for f in bdir.iterdir() if f.name.startswith("."))


def test_two_backups_in_one_second_are_two_snapshots(paths, project, monkeypatch) -> None:
    monkeypatch.setattr(backup, "utc_now", lambda: STEPPED_BACK)
    rc, first = _snapshot(paths, b"first")
    assert rc == 0 and first is not None
    # A rollback is now paired with the first one.
    write_state(paths.project_deploy_state(P), {"pre_deploy_snapshot": first})

    rc, second = _snapshot(paths, b"second")

    assert rc == 0 and second is not None and second != first
    assert (project / first).read_bytes() == b"first"
    assert (project / second).read_bytes() == b"second"
    assert first in paired_snapshots(paths, P)
    assert {p.name for p in list_snapshots(paths, P)} == {first, second}
    assert [parse_snapshot(project / n, P)[1] for n in (first, second)] == [
        BackupKind.PREDEPLOY] * 2
    assert _leftovers(project) == []


def test_a_name_that_is_taken_is_refused_and_the_next_backup_works(
        paths, project, capsys) -> None:
    """The publication itself never replaces: forced onto a paired
    snapshot's name, the backup fails and that snapshot keeps its data."""
    paired = f"{P}-2026-06-01T000000-predeploy.tar.gz.age"
    (project / paired).write_bytes(b"original paired data")
    write_state(paths.project_deploy_state(P), {"pre_deploy_snapshot": paired})

    with patch.object(backup_cmd, "backup_filename", return_value=paired):
        result = _snapshot(paths, b"new data")

    assert result == (1, None)
    assert (project / paired).read_bytes() == b"original paired data"
    assert "already exists" in capsys.readouterr().err
    assert _leftovers(project) == []

    rc, name = _snapshot(paths, b"new data")
    assert rc == 0 and name not in (None, paired)
    assert (project / name).read_bytes() == b"new data"
    assert (project / paired).read_bytes() == b"original paired data"


def test_after_the_clock_steps_back_the_snapshot_is_new_named_and_kept(
        paths, project, monkeypatch) -> None:
    """The clock returns to a second a stored snapshot is named for, with
    retention already full of later-dated ones: the new snapshot gets its
    own name, replaces nothing, and its own retention pass does not prune it."""
    stored = [f"{P}-2026-06-0{day}T000000-predeploy.tar.gz.age" for day in range(1, 6)]
    for name in stored:
        (project / name).write_bytes(b"original " + name.encode())
    write_state(paths.project_deploy_state(P), {"pre_deploy_snapshot": stored[0]})
    monkeypatch.setattr(backup, "utc_now", lambda: STEPPED_BACK)

    rc, name = _snapshot(paths, b"after the step back")

    assert rc == 0 and name is not None and name not in stored
    assert (project / name).read_bytes() == b"after the step back"
    assert (project / stored[0]).read_bytes() == b"original " + stored[0].encode()
    assert {p.name for p in list_snapshots(paths, P)} == {*stored, name}


def test_while_snapshots_are_dated_ahead_of_the_clock_nothing_is_pruned(
        paths, project, monkeypatch, capsys) -> None:
    """Three nightlies taken while the clock ran a month ahead fill
    retention. Back on the right date, each night's snapshot sorted as the
    oldest: it was pruned the night after, and the three stale ones stayed."""
    keep_three = {**MANIFEST, "backup": {**MANIFEST["backup"], "retention": 3}}
    ahead = [f"{P}-2026-12-0{day}T020000-nightly.tar.gz.age" for day in (1, 2, 3)]
    for name in ahead:
        (project / name).write_bytes(b"taken while the clock ran ahead")
    taken = []
    for day in (10, 11, 12):
        monkeypatch.setattr(
            backup, "utc_now", lambda day=day: datetime(2026, 11, day, 2, tzinfo=timezone.utc))
        rc, name = _snapshot(paths, b"night %d" % day, BackupKind.NIGHTLY, keep_three)
        assert rc == 0
        taken.append(name)
    assert {p.name for p in list_snapshots(paths, P)} == {*ahead, *taken}
    warned = capsys.readouterr().err
    assert "Not pruning old nightly backups of demo" in warned
    assert f"3 snapshot(s) are dated ahead of the clock (the latest: {ahead[2]})" in warned

    # The clock passes them: the names are in the order taken again.
    monkeypatch.setattr(backup, "utc_now", lambda: datetime(2026, 12, 4, 2, tzinfo=timezone.utc))
    rc, newest = _snapshot(paths, b"december", BackupKind.NIGHTLY, keep_three)
    assert rc == 0
    assert {p.name for p in list_snapshots(paths, P)} == {ahead[1], ahead[2], newest}


def test_snapshots_named_the_older_ways_still_parse_and_prune(paths, project) -> None:
    """Snapshots already on disk keep their names and stay restorable."""
    old = [project / f"{P}-2026-01-0{d}T020000.tar.gz.age" for d in (1, 2)]
    kinded = [project / f"{P}-2026-01-0{d}T020000-nightly.tar.gz.age" for d in (3, 4)]
    for f in [*old, *kinded]:
        f.write_bytes(b"x")
    assert [parse_snapshot(f, P) for f in [old[0], kinded[0]]] == [
        ("2026-01-01T020000", BackupKind.NIGHTLY), ("2026-01-03T020000", BackupKind.NIGHTLY)]

    rc, name = _snapshot(paths, b"tonight", BackupKind.NIGHTLY)

    assert rc == 0 and parse_snapshot(project / name, P)[1] is BackupKind.NIGHTLY
    # MANIFEST sets no retention: 7 nightly snapshots are kept, so none goes.
    assert all(f.exists() for f in [*old, *kinded])
    pruned = backup.prune_backups(project, P, BackupKind.NIGHTLY, 2, keep={name})
    assert sorted(f.name for f in pruned) == sorted(f.name for f in [*old, kinded[0]])
    assert (project / name).exists() and kinded[1].exists()
