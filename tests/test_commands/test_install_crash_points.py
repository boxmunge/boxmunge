"""Every crash point of a bundle deploy (spec, 'Promote (transaction phases)')."""
from __future__ import annotations

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn
from tests.bundle_helpers import manifest_text, place_bundle
from tests.txn_helpers import crash_at, docker_off, fake_backups, flaky_hook, hook_runs

V1, V2 = "2026-10-16T090000000000", "2026-10-16T100000000000"
POINTS = ["txn.before_open", "txn.committed", "txn.previous_kept", "txn.installed",
          "txn.hook_started", "txn.switching", "txn.replaced", "txn.switched"]


@pytest.mark.parametrize("point", POINTS)
def test_crash_then_rerun_finishes_truthfully(paths, tmp_path, point) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    hook = flaky_hook(tmp_path, failures=0)
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n", "manifest.yml":
                 manifest_text(backup="postgres") + f"deploy:\n  pre_deploy: {hook}\n"})
    taken: list[dict] = []
    with docker_off() as up, fake_backups(taken):
        assert run_deploy("myapp", paths, ref=V1) == 0
        taken.clear()
        assert crash_at(point, lambda: run_deploy("myapp", paths, ref=V2)) == 137
        up.reset_mock()
        assert run_deploy("myapp", paths) == 0
    assert load_txn(paths, "myapp") is None
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "v2\n"
    prev = paths.project_releases("myapp")
    assert (prev / "previous" / "VERSION").read_text() == "v1\n"   # never half-installed code
    # The child's snapshot is recorded in the child's memory only. The rerun
    # takes none, except after before_open: no transaction existed yet, and a
    # new snapshot of unchanged data is equally valid.
    assert len(taken) == (1 if point == "txn.before_open" else 0)
    if point in ("txn.switching", "txn.replaced", "txn.switched"):
        assert hook_runs(tmp_path) == 1                             # the hook is not rerun
