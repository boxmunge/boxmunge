"""Every crash point of a promote (spec, 'Promote (transaction phases)'),
and --abandon of a promote: the slot stays promotable until the switch."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands import promote_cmd
from boxmunge.commands.install_abandon import run_abandon
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.intake import check_installable
from boxmunge.release_txn import load_txn
from boxmunge.staged_release import load_slot
from tests.bundle_helpers import manifest_text
from tests.stage_helpers import V1, prod_and_stage, staging_docker_off
from tests.txn_helpers import crash_at, fake_backups, flaky_hook, hook_runs

POINTS = ["txn.before_open", "txn.committed", "txn.previous_kept", "txn.installed",
          "txn.hook_started", "txn.switching", "txn.replaced", "txn.switched"]
# replace_release had not returned yet at these points, so the slot is not retired.
UNSWITCHED = POINTS[:-1]


def _staged(paths, tmp_path):
    hook = flaky_hook(tmp_path, failures=0)
    return prod_and_stage(
        paths, prod_files={"manifest.yml": manifest_text(backup="postgres")},
        staged_files={"manifest.yml": manifest_text(backup="postgres")
                      + f"deploy:\n  pre_deploy: '{hook}'\n"})


@pytest.mark.parametrize("point", POINTS)
def test_promote_crash_then_rerun_finishes_truthfully(paths, tmp_path, capsys,
                                                      point) -> None:
    pdir = _staged(paths, tmp_path)
    staged_id = load_slot(paths, "myapp").id
    taken: list[dict] = []
    with staging_docker_off(), fake_backups(taken):
        assert crash_at(point, lambda: run_promote("myapp", paths)) == 137
        txn = load_txn(paths, "myapp")
        slot = load_slot(paths, "myapp")
        assert slot.state == ("ready" if point in UNSWITCHED else "retired")
        if point == "txn.before_open":
            assert txn is None
        else:
            assert (txn.source, txn.staged_id) == ("staged", staged_id)
            capsys.readouterr()
            assert run_unstage("myapp", paths) == 1        # the install needs the slot
            assert "is being promoted from this staged release" in capsys.readouterr().err
            assert load_slot(paths, "myapp") == slot       # unstage changed nothing
        with patch.object(promote_cmd, "check_installable",
                          wraps=check_installable) as installable:
            assert run_promote("myapp", paths) == 0
    out = capsys.readouterr().out
    if point == "txn.before_open":
        installable.assert_called_once()                  # a fresh promote
    elif point == "txn.switched":
        installable.assert_not_called()                   # retired: teardown only
        assert "already live in production" in out
    else:
        installable.assert_not_called()                   # a resume: partly installed
        assert "Resuming the install of" in out
    assert load_txn(paths, "myapp") is None and load_slot(paths, "myapp") is None
    assert (pdir / "VERSION").read_text() == "v2\n"
    previous = paths.project_releases("myapp") / "previous"
    assert (previous / "VERSION").read_text() == "v1\n"
    assert hook_runs(tmp_path) == 1
    # As for a bundle deploy (the child's snapshot is in its memory only):
    # the rerun takes none, except after before_open, when no transaction
    # recorded the child's.
    assert len(taken) == (1 if point == "txn.before_open" else 0)


@pytest.mark.parametrize("point", ["txn.switched", "slot.discarding"])
def test_promote_announces_once_however_it_is_killed(paths, tmp_path, capsys,
                                                       point) -> None:
    """Killed before staging was down (txn.switched) or while dropping the
    announced slot (slot.discarding): the rerun says production is promoted
    and logs and fires the promotion exactly once."""
    pdir = _staged(paths, tmp_path)
    with staging_docker_off(), fake_backups([]):
        assert crash_at(point, lambda: run_promote("myapp", paths)) == 137
        capsys.readouterr()
        assert run_promote("myapp", paths, dry_run=True) == 0
        assert run_promote("myapp", paths) == 0
        out = capsys.readouterr().out
        assert run_promote("myapp", paths) == 1          # nothing is staged now
    assert "promoted to production" in out
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert not [p for p in paths.project_releases("myapp").iterdir()
                if p.name.startswith("staged")]
    log = paths.log_file.read_text()
    assert log.count("from staging to production") == 1
    assert log.count("failed to fire promote webhook") == 1


def test_abandoning_a_promote_leaves_the_slot_promotable(paths) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.commands.rollback import find_rollback_target
    from boxmunge.commands.stage_cmd import run_stage
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.stage_helpers import V2
    v0 = "2026-10-16T080000000000"
    add_project("myapp", paths)
    for ts, version in ((v0, "v0"), (V1, "v1"), (V2, "v2")):
        place_bundle(paths, timestamp=ts, files={"VERSION": f"{version}\n"})
    pdir = paths.project_dir("myapp")
    previous = paths.project_releases("myapp") / "previous"
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths, ref=v0) == 0
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_stage("myapp", paths, ref=V2) == 0
        assert crash_at("txn.installed", lambda: run_promote("myapp", paths)) == 137
        assert (pdir / "VERSION").read_text() == "v2\n"
        assert (previous / "VERSION").read_text() == "v1\n"
        docker["up"].reset_mock()
        assert run_abandon("myapp", paths) == 0
        docker["up"].assert_not_called()
        assert load_txn(paths, "myapp") is None
        assert (pdir / "VERSION").read_text() == "v1\n"     # the code is back
        assert (previous / "VERSION").read_text() == "v0\n"  # and previous/ with it
        assert find_rollback_target(paths, "myapp").ref == f"myapp-{v0}"
        assert load_slot(paths, "myapp").state == "ready"
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert (previous / "VERSION").read_text() == "v1\n"
    assert load_slot(paths, "myapp") is None and load_txn(paths, "myapp") is None
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"
