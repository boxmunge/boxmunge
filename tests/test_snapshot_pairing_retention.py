"""T7: per-kind retention never prunes a snapshot something is paired with.

Rollback needs the exact snapshot its target pairs with. Five deploy
attempts that each take a pre-deploy snapshot but fail before switching
used to evict the one previous.json names (predeploy keeps 5), and
rollback then refused. The pairings: the kept previous release's
data_snapshot, the deploy state's pre_deploy_snapshot (a git project's
rollback), an open install's snapshot, and the snapshot pause or data
chown recorded for the next deploy.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.backup import BackupKind
from boxmunge.commands import backup_cmd
from boxmunge.pending_snapshot import record_pending
from boxmunge.release import previous_dir
from boxmunge.release_txn import open_txn
from boxmunge.state import write_state

P = "myapp"
PAIRED = f"{P}-2026-01-01T000000-predeploy.tar.gz.age"
NEWER = [f"{P}-2026-01-0{d}T000000-predeploy.tar.gz.age" for d in range(2, 7)]


def _previous(paths) -> None:
    previous_dir(paths, P).mkdir(parents=True)
    (paths.project_releases(P) / "previous.json").write_text(json.dumps({
        "ref": f"{P}-v1", "data_snapshot": PAIRED, "replaced_at": "t", "replaced_by": "deploy"}))


def _deploy_state(paths) -> None:
    write_state(paths.project_deploy_state(P), {"current_ref": f"{P}-v2",
                                               "pre_deploy_snapshot": PAIRED})


def _open_install(paths) -> None:
    paths.project_releases(P).mkdir(parents=True, exist_ok=True)
    open_txn(paths, P, source="bundle", ref=f"{P}-v3", replaced_ref=f"{P}-v2",
             staged_id=None, snapshot=PAIRED)


def _pending(paths) -> None:
    write_state(paths.project_deploy_state(P), {"current_ref": f"{P}-v2"})
    record_pending(paths, P, PAIRED, "pause", "web", [f"{P}-web-1"])


def _backup(paths, kind=BackupKind.PREDEPLOY) -> int:
    def dump(paths_, project, *a, **k) -> Path:
        raw = paths_.project_backups(project) / "raw.tmp"
        raw.write_text("dump")
        return raw

    def encrypt(src: Path, out: Path, paths_) -> None:
        out.write_text(src.read_text())
    with patch.object(backup_cmd, "execute_dump", dump), \
            patch.object(backup_cmd._backup, "encrypt_file", encrypt):
        return backup_cmd._run_backup_inner(P, paths, "cat /data", "web", kind, 5)


@pytest.fixture
def backups(paths) -> Path:
    bdir = paths.project_backups(P)
    bdir.mkdir(parents=True)
    for name in [PAIRED, *NEWER]:
        (bdir / name).write_text("old")
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    return bdir


@pytest.mark.parametrize("pair", [_previous, _deploy_state, _open_install, _pending],
                         ids=["previous.json", "pre_deploy_snapshot", "open install",
                              "pending snapshot"])
def test_the_paired_snapshot_survives_retention(paths, backups, pair) -> None:
    pair(paths)
    assert _backup(paths) == 0
    assert (backups / PAIRED).exists()
    # Retention still prunes the oldest unpaired ones.
    assert not (backups / NEWER[0]).exists()
    assert (backups / NEWER[1]).exists()


def test_without_a_pairing_the_oldest_is_pruned(paths, backups) -> None:
    assert _backup(paths) == 0
    assert not (backups / PAIRED).exists() and not (backups / NEWER[0]).exists()


def test_an_unreadable_pairing_prunes_nothing_and_says_why(paths, backups, capsys) -> None:
    previous_dir(paths, P).mkdir(parents=True)
    (paths.project_releases(P) / "previous.json").write_text("{not json")
    assert _backup(paths) == 0
    assert (backups / PAIRED).exists() and (backups / NEWER[0]).exists()
    assert "Not pruning old predeploy backups" in capsys.readouterr().err


def test_a_previous_json_that_is_not_utf8_warns_and_the_backup_succeeds(
        paths, backups, capsys) -> None:
    """Review of #159 (P3-3): a UnicodeDecodeError escaped _read_meta and
    aborted the backup instead of suppressing the prune with a warning."""
    previous_dir(paths, P).mkdir(parents=True)
    (paths.project_releases(P) / "previous.json").write_bytes(b"\xff\xfe")
    assert _backup(paths) == 0
    assert (backups / PAIRED).exists()
    assert "Not pruning old predeploy backups" in capsys.readouterr().err
