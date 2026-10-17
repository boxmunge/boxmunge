"""Cores never take the project lock (fileutil 'Lock order')."""
from __future__ import annotations

import sys
from contextlib import nullcontext

from boxmunge import fileutil
from boxmunge.commands import install_abandon, promote_cmd, rollback, stage_cmd, unstage_cmd
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V3, prod_and_stage, staging_docker_off


def test_cores_never_take_the_lock(paths, monkeypatch) -> None:
    """The state is built through the entry points first; only then is the
    lock replaced, at every module's binding of it, by one that records each
    taking, and the cores run directly."""
    prod_and_stage(paths)
    place_bundle(paths, timestamp=V3)
    real = fileutil.project_lock
    bound = [mod for name, mod in list(sys.modules.items())
             if name.startswith("boxmunge") and getattr(mod, "project_lock", None) is real]
    assert {fileutil, promote_cmd, stage_cmd, unstage_cmd} <= set(bound)
    taken: list[tuple] = []

    def lock(*a, **k):
        # Recorded, not raised: a core's `except Exception` could swallow a raise.
        taken.append(a)
        return nullcontext()

    for mod in bound:
        monkeypatch.setattr(mod, "project_lock", lock)
    with staging_docker_off():
        assert stage_cmd.stage_locked("myapp", paths, ref=V3) == 0
        assert promote_cmd.promote_locked("myapp", paths) == 0
        assert rollback.rollback_locked("myapp", paths) == 0
        assert install_abandon.abandon_locked("myapp", paths) == 1   # nothing open
        assert unstage_cmd.unstage_locked("myapp", paths) == 1       # nothing staged
    assert taken == [], f"a core took the project lock: {taken}"
