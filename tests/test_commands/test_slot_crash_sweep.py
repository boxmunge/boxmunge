"""Kill promote and unstage before each filesystem change they make, in
turn (review of #80): a rerun finishes truthfully, production is as it
should be, nothing of the slot is left, and promote's log line and webhook
are sent exactly once.

A forked child counts every rename, replace, unlink, rmdir, mkdir,
symlink, remove and rmtree and dies at the Nth, as a SIGKILL would; the
sweep runs until the child finishes without reaching N.
"""
from __future__ import annotations

import itertools
import os
import shutil
from collections.abc import Callable

from boxmunge import log
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.paths import BoxPaths
from boxmunge.release_txn import load_txn
from boxmunge.staged_release import load_slot
from tests.bundle_helpers import tree_snapshot
from tests.stage_helpers import prod_and_stage, staging_docker_off

_OPS = ("rename", "replace", "unlink", "rmdir", "mkdir", "symlink", "remove")
_DIRS = ("bin", "config", "caddy/sites", "projects", "state/health", "state/deploy",
         "templates/project", "docs", "logs", "inbox/.tmp", "inbox/.consumed")


def _box(root) -> BoxPaths:
    for sub in _DIRS:
        (root / sub).mkdir(parents=True)
    log._reset_logger()  # each box logs to its own file
    return BoxPaths(root=root)


def _killed_at(n: int, fn: Callable[[], object]) -> int:
    pid = os.fork()
    if pid == 0:
        count = [0]

        def counted(real):
            def call(*a, **k):
                count[0] += 1
                if count[0] == n:
                    os._exit(137)
                return real(*a, **k)
            return call
        for name in _OPS:
            setattr(os, name, counted(getattr(os, name)))
        shutil.rmtree = counted(shutil.rmtree)
        try:
            with staging_docker_off():
                fn()
        finally:
            os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def _sweep(tmp_path, op: Callable[[BoxPaths], object],
           check: Callable[[BoxPaths, int, dict], None]) -> int:
    for n in itertools.count(1):
        paths = _box(tmp_path / f"kill-{n}")
        prod_and_stage(paths)
        before = _production(paths)
        if _killed_at(n, lambda: op(paths)) == 0:
            return n
        check(paths, n, before)


def _production(paths: BoxPaths) -> dict:
    snap = tree_snapshot(paths.project_dir("myapp"))
    return {k: v for k, v in snap.items() if not k.startswith(".releases/staged")}


def _no_slot_left(paths: BoxPaths) -> None:
    assert load_slot(paths, "myapp") is None and load_txn(paths, "myapp") is None
    left = [p.name for p in paths.project_releases("myapp").iterdir()
            if p.name.startswith("staged")]
    assert left == []


def _logged(paths: BoxPaths, text: str) -> int:
    return paths.log_file.read_text().count(text) if paths.log_file.exists() else 0


def test_promote_killed_anywhere_finishes_on_rerun(tmp_path, capsys) -> None:
    def check(paths, n, _before):
        capsys.readouterr()
        with staging_docker_off():
            assert run_promote("myapp", paths) == 0, f"rerun after kill #{n}"
        out = capsys.readouterr().out
        assert "promoted" in out and "No staged release" not in out, n
        pdir = paths.project_dir("myapp")
        assert (pdir / "VERSION").read_text() == "v2\n"
        assert (paths.project_releases("myapp") / "previous" / "VERSION").read_text() == "v1\n"
        _no_slot_left(paths)
        assert _logged(paths, "from staging to production") == 1, n
        assert _logged(paths, "failed to fire promote webhook") == 1, n
    assert _sweep(tmp_path, lambda paths: run_promote("myapp", paths), check) > 30


def test_unstage_killed_anywhere_finishes_on_rerun(tmp_path, capsys) -> None:
    def check(paths, n, before):
        assert _production(paths) == before
        capsys.readouterr()
        with staging_docker_off():
            assert run_unstage("myapp", paths) == 0, f"rerun after kill #{n}"
        assert "No staging found" not in capsys.readouterr().err, n
        assert _production(paths) == before
        _no_slot_left(paths)
        assert _logged(paths, "Unstaged") == 1, n
    assert _sweep(tmp_path, lambda paths: run_unstage("myapp", paths), check) > 5
