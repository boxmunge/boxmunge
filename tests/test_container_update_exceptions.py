# SPDX-License-Identifier: Apache-2.0
"""Audit R04: an exception or interruption anywhere between the pull and the
recreate puts every image tag back, so the NEXT recreation runs the images the
project ran before. The original failure survives, and a tag that cannot go
back is reported with it."""
from __future__ import annotations

import pytest

from boxmunge import container_update as cu
from boxmunge import container_update_tags
from boxmunge.commands import backup_cmd
from boxmunge.commands.container_update_cmd import _dry_run_target
from tests.test_container_update import _NEW, _OLD
from tests.test_container_update_abort import (
    _ALL_OLD, _docker_tag_fails_for_db, _project, _raiser, _restart,
)


def _real_backup(paths, monkeypatch):
    """backup_locked runs for real, from the project's manifest; the update
    module's own stub (_project) is taken out."""
    monkeypatch.setattr(cu, "backup_locked", backup_cmd.backup_locked)
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("AGE-SECRET-KEY-test")


def _stale_removal_fails(paths, monkeypatch, docker):
    _real_backup(paths, monkeypatch)
    monkeypatch.setattr(backup_cmd, "remove_stale_dumps", _raiser(PermissionError("denied")))


def _backup_dir_is_a_file(paths, monkeypatch, docker):
    _real_backup(paths, monkeypatch)
    paths.project_backups(docker.project).write_text("not a directory")


def _pruning_fails(paths, monkeypatch, docker):
    _real_backup(paths, monkeypatch)
    dump = paths.project_backups(docker.project) / "dump.tar.gz"
    paths.project_backups(docker.project).mkdir(exist_ok=True)
    dump.write_text("x")
    monkeypatch.setattr(backup_cmd, "execute_dump", lambda *a, **kw: dump)
    monkeypatch.setattr(backup_cmd._backup, "encrypt_file",
                        lambda src, dst, paths_: dst.write_text("enc"))
    monkeypatch.setattr(backup_cmd, "prune_unpaired",
                        _raiser(OSError("read-only file system")))


@pytest.mark.parametrize("prepare, expected", [
    (_stale_removal_fails, "PermissionError: denied"),
    (_backup_dir_is_a_file, "NotADirectoryError"),
    (_pruning_fails, "read-only file system"),
])
def test_backup_exception_puts_the_tags_back(prepare, expected, paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    prepare(paths, monkeypatch, docker)

    result = cu.update_target_locked(paths, target)

    assert result["status"] == "failed" and result["reason"].startswith("exception: ")
    assert result["tags_not_restored"] == [] and docker.ups == 0
    assert result["reason"].count(expected) == 1
    assert docker.tags == {"nginx:1.25": _OLD, "postgres:17": _OLD}
    assert _restart(docker) == _ALL_OLD


def test_backup_exception_and_a_stuck_tag_are_both_reported(
        paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    _pruning_fails(paths, monkeypatch, docker)
    _docker_tag_fails_for_db(monkeypatch, docker)

    result = cu.update_target_locked(paths, target)

    assert result["status"] == "failed" and result["tags_not_restored"] == ["postgres:17"]
    assert "read-only file system" in result["reason"]
    assert "tag_restore_failed: postgres:17" in result["reason"]
    assert _restart(docker) == {"web": _OLD, "db": _NEW}


@pytest.mark.parametrize("interrupt", ["backup", "pull", "guard"])
def test_interruption_puts_the_tags_back_and_propagates(
        interrupt, paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    if interrupt == "backup":
        monkeypatch.setattr(cu, "backup_locked", _raiser(KeyboardInterrupt()))
    elif interrupt == "guard":
        monkeypatch.setattr(cu, "guard_pull", _raiser(KeyboardInterrupt()))
    else:
        def pull(*a, **kw):
            docker._pull()
            raise KeyboardInterrupt
        monkeypatch.setattr(cu, "compose_pull", pull)

    with pytest.raises(KeyboardInterrupt):
        cu.update_target_locked(paths, target)

    assert docker.ups == 0
    assert docker.tags == {"nginx:1.25": _OLD, "postgres:17": _OLD}
    assert _restart(docker) == _ALL_OLD


def test_interruption_with_a_stuck_tag_keeps_the_interrupt_and_says_so(
        paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    monkeypatch.setattr(cu, "backup_locked", _raiser(KeyboardInterrupt()))
    _docker_tag_fails_for_db(monkeypatch, docker)
    monkeypatch.setattr(container_update_tags, "log_error", lambda *a, **kw: None)

    with pytest.raises(KeyboardInterrupt) as info:
        cu.update_target_locked(paths, target)

    assert any("postgres:17" in n and "tag_restore_failed" in n for n in info.value.__notes__)


def test_dry_run_exception_puts_the_tags_back(paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    monkeypatch.setattr("boxmunge.user_drift.guard_pull", _raiser(OSError("disk error")))

    result = _dry_run_target(paths, target)

    assert result["status"] == "failed"
    assert result["reason"] == "exception: OSError: disk error"
    assert result["tags_not_restored"] == [] and _restart(docker) == _ALL_OLD


def test_dry_run_interruption_puts_the_tags_back(paths, monkeypatch, fake_containers) -> None:
    docker, target = _project(paths, monkeypatch, fake_containers)
    monkeypatch.setattr("boxmunge.user_drift.guard_pull", _raiser(KeyboardInterrupt()))

    with pytest.raises(KeyboardInterrupt):
        _dry_run_target(paths, target)

    assert _restart(docker) == _ALL_OLD
