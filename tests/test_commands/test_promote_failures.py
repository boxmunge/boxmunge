"""Promote's failure reports: no traceback, the open install's options, and
advice that fits a promote."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from boxmunge.commands import promote_cmd
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.release_txn import load_txn
from boxmunge.staged_release import SlotError, load_slot
from boxmunge.staging_isolation import StagingIsolationError
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V3, prod_and_stage, staging_docker_off
from tests.txn_helpers import hook_manifest


def _logged_errors(paths) -> list[str]:
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    return [e["msg"] for e in entries if e["level"] == "error"]


def _second_load_raises(error: Exception):
    """promote_cmd.load_slot reads the slot as it is the first time (the
    eligibility check), then raises."""
    calls: list[int] = []

    def load(paths, project):
        calls.append(1)
        if len(calls) > 1:
            raise error
        return load_slot(paths, project)
    return load


@pytest.mark.parametrize("seam,error", [
    ("update_meta", OSError("No space left on device")),
    ("load_slot", SlotError("cannot read meta.json")),
])
def test_a_failed_retire_is_reported_with_the_installs_options(
        paths, capsys, seam, error) -> None:
    pdir = prod_and_stage(paths)
    fake = (_second_load_raises(error) if seam == "load_slot" else
            lambda *a, **k: (_ for _ in ()).throw(error))
    with staging_docker_off(), patch.object(promote_cmd, seam, side_effect=fake):
        assert run_promote("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "recording the staged slot as retired failed" in err and str(error) in err
    if seam == "update_meta":
        assert "rerun 'promote myapp' to finish it" in err
    else:   # an unreadable record: the rerun would refuse too
        assert "cannot resume without it" in err and "'rollback myapp' restores" in err
    assert (pdir / "VERSION").read_text() == "v2\n"           # production was switched
    assert load_txn(paths, "myapp").phase == "switching"      # the install stays open
    assert any("retired failed" in m for m in _logged_errors(paths))
    with staging_docker_off():
        assert run_promote("myapp", paths) == 0               # and a rerun finishes it
    assert load_txn(paths, "myapp") is None and load_slot(paths, "myapp") is None


def test_a_failed_promote_with_an_unreadable_slot_is_reported(paths, capsys) -> None:
    prod_and_stage(paths, staged_files={"manifest.yml": hook_manifest("false")})
    with staging_docker_off(), patch.object(
            promote_cmd, "load_slot", side_effect=_second_load_raises(
                SlotError("cannot read meta.json"))):
        assert run_promote("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "cannot read meta.json" in err and "cannot resume without it" in err
    assert "'rollback myapp' restores" in err
    assert any("cannot read meta.json" in m for m in _logged_errors(paths))
    assert load_txn(paths, "myapp").phase == "hook_started"


def test_a_promote_sharing_with_staging_says_to_stage_a_fixed_release(paths, capsys) -> None:
    prod_and_stage(paths)
    with staging_docker_off(), patch("boxmunge.commands.deploy_tree.check_install_isolation",
                                     side_effect=StagingIsolationError("shares x")):
        assert run_promote("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "stage a fixed release" in err and "unstage first" not in err
    assert load_slot(paths, "myapp").state == "ready" and load_txn(paths, "myapp") is None


def test_a_deploy_sharing_with_staging_keeps_its_advice(paths, capsys) -> None:
    prod_and_stage(paths)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with staging_docker_off(), patch("boxmunge.commands.deploy_tree.check_install_isolation",
                                     side_effect=StagingIsolationError("shares x")):
        assert run_deploy("myapp", paths, ref=V3) == 1
    assert "Fix the release, or unstage first." in capsys.readouterr().err
