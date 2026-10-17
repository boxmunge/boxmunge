"""The migration and its rollback on a real daemon, whole and killed at every step.

Every kill must leave a box that still runs unremapped or that the same
command, run again, completes; and from any kill, userns-rollback must put
the box back as it was. The project's container sees the same files, owners
and modes before the migration, after it and after the rollback.
"""
from __future__ import annotations

import os
import time

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.userns import offset as uo
from boxmunge.userns.engine import migrate
from boxmunge.userns.journal import load_journal
from boxmunge.userns.rollback import rollback
from boxmunge.userns.switch import MigrationError
from tests.integration.userns import migration_box as mb
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.crashsweep import count, crash_before, crash_points
from tests.integration.userns.dockerd import FakeTimers, ProcessDaemon

pytestmark = USERNS_DIND


@pytest.fixture(scope="module")
def box(tmp_path_factory):
    root = tmp_path_factory.mktemp("migration") / "boxmunge"
    for sub in ("config", "projects", "state/deploy", "state/health", "logs", "caddy/sites",
                "system", "upgrade-state"):
        (root / sub).mkdir(parents=True)
    paths = BoxPaths(root=root)
    with pytest.MonkeyPatch.context() as mp:
        mb.stand_ins(mp)
        mb.make_box(paths)
        before = (mb.view(), mb.host_owners(paths))
        yield paths, before, root.parent / "img"
        journal = load_journal(paths)
        if journal is not None and journal.phase not in ("rolled-back",):
            _rollback(paths, root.parent / "img")
        mb.docker("compose", "-p", mb.PROJECT, "down", "-v", cwd=paths.project_dir(mb.PROJECT),
                  check=False)


def _migrate(paths, images) -> None:
    migrate(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=images)


def _rollback(paths, images) -> None:
    rollback(paths, daemon=ProcessDaemon(), timers=FakeTimers(), images_dir=images)


def _as_before(paths, before) -> None:
    assert not mb.daemon_remapped() and uo.recorded_offset(paths) is None
    assert (mb.view(), mb.host_owners(paths)) == before


def _migrated(paths, before) -> None:
    s = uo.remap_offset(paths)
    assert s > 0 and mb.daemon_remapped() and load_journal(paths).phase == "applied"
    assert mb.view() == before[0]
    assert mb.host_owners(paths) == {k: (u + s, g + s) for k, (u, g) in before[1].items()}


def test_migrate_then_roll_back(box) -> None:
    paths, before, images = box
    _as_before(paths, before)
    _migrate(paths, images)
    _migrated(paths, before)
    with pytest.raises(MigrationError, match="already applied"):
        _migrate(paths, images)
    _rollback(paths, images)
    _as_before(paths, before)
    assert load_journal(paths).phase == "rolled-back"
    s = load_journal(paths).offset
    assert not os.path.lexists(f"/var/lib/docker/{s}.{s}")


def _recover(paths, images, before, n: int) -> None:
    """After a kill: odd kills resume the migration, even ones roll it back."""
    journal = load_journal(paths)
    if journal is None:  # killed before the journal: nothing changed
        _as_before(paths, before)
        return
    if n % 2:
        _migrate(paths, images)
        _migrated(paths, before)
    _rollback(paths, images)
    _as_before(paths, before)


def test_a_kill_at_any_step_of_the_migration_is_recoverable(box) -> None:
    paths, before, images = box
    labels = count(lambda: _migrate(paths, images))
    _rollback(paths, images)
    points = crash_points(labels)
    print(f"\nmigration: {len(labels)} changes, {len(points)} kill points")
    started = time.monotonic()
    for n in points:
        assert crash_before(n, lambda: _migrate(paths, images)) == 137, (n, labels[n - 1])
        try:
            _recover(paths, images, before, n)
        except BaseException as e:
            raise AssertionError(f"after a kill before change {n} ({labels[n - 1]}): {e}") from e
    print(f"swept in {time.monotonic() - started:.0f}s")


def test_a_kill_at_any_step_of_the_rollback_is_recoverable(box) -> None:
    paths, before, images = box
    _migrate(paths, images)
    labels = count(lambda: _rollback(paths, images))
    points = crash_points(labels)
    print(f"\nrollback: {len(labels)} changes, {len(points)} kill points")
    for n in points:
        _migrate(paths, images)
        assert crash_before(n, lambda: _rollback(paths, images)) == 137, (n, labels[n - 1])
        try:
            _rollback(paths, images)
            _as_before(paths, before)
        except BaseException as e:
            raise AssertionError(f"after a kill before rollback change {n} "
                                 f"({labels[n - 1]}): {e}") from e
