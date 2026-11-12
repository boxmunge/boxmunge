# SPDX-License-Identifier: Apache-2.0
"""A pause or quarantine record the upgrade cannot read (corrupt, or a link
whose target is gone) excludes that project, "left as is", and is
reported: it is not migrated, regenerated or restarted, its containers keep
running as they are, and the upgrade goes on for every other project. The
dry run reports the same exclusion. Never a failed upgrade."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.upgrade_report import check_upgrade
from boxmunge.commands.upgrade_steps import restart_projects
from boxmunge.health_checks.projects import check_lifecycle_blocked
from boxmunge.pause import mark_pause_complete, write_paused_state
from boxmunge.project_registry import add_project
from boxmunge.upgrade_exclusions import apply_projects, notify_exclusions
from tests.bundle_helpers import manifest_text, place_bundle, tree_snapshot
from tests.stage_helpers import V1
from tests.test_commands.cve_helpers import seed_quarantine
from tests.txn_helpers import docker_off

P, OTHER = "myapp", "other"


def _deployed(paths, name: str, ulid: str) -> None:
    add_project(name, paths)
    place_bundle(paths, project=name, timestamp=V1,
                 files={"manifest.yml": manifest_text(name, ulid)})
    with docker_off():
        assert run_deploy(name, paths, ref=V1) == 0


def _record(paths, kind: str):
    return (paths.project_paused_state(P) if kind == "pause"
            else paths.project_quarantine_state(P))


@pytest.fixture(params=[(k, f) for k in ("pause", "quarantine") for f in ("dangling", "corrupt")],
                ids=lambda p: f"{p[0]}-{p[1]}")
def box(request, paths, tmp_path):
    kind, form = request.param
    _deployed(paths, P, "01TESTULID0000000000000000")
    _deployed(paths, OTHER, "01TESTULID0000000000000001")
    if kind == "pause":
        write_paused_state(P, paths, reason="maintenance")
        mark_pause_complete(P, paths)
    else:
        seed_quarantine(paths, P)
    record = _record(paths, kind)
    record.unlink()
    if form == "dangling":
        record.symlink_to(tmp_path / "gone.json")
    else:
        record.write_text("{broken")
    return paths, kind, record


def test_the_project_is_left_as_is_and_the_others_are_upgraded(box) -> None:
    paths, kind, record = box
    before = tree_snapshot(paths.project_dir(P))
    _m, regen, excluded = apply_projects(paths)
    assert P in excluded.unreadable and P in excluded.names()
    assert regen.processed == [OTHER]
    assert tree_snapshot(paths.project_dir(P)) == before
    why = excluded.unreadable[P]
    assert str(record) in why and "cannot be read" in why and "remove it as root" in why
    assert "`boxmunge prod-deploy myapp --redeploy`" in why
    assert ("`boxmunge pause myapp --no-snapshot`" in why) == (kind == "pause")
    assert ("`boxmunge security scan myapp`" in why) == (kind == "quarantine")
    log = paths.log_file.read_text()
    assert f"Left {P} as it is" in log and str(record) in log
    started: list[str] = []
    with patch("boxmunge.commands.upgrade_steps._restart_locked",
               lambda paths_, d, name, refused, result: started.append(name)):
        restart_projects(paths, refused={}, excluded=excluded.names())
    assert started == [OTHER]
    with patch("boxmunge.upgrade_exclusions.notify") as summary:
        notify_exclusions(paths, excluded)
    [call] = [c for c in summary.call_args_list if P in c.args[2]]
    assert call.kwargs["priority"] == 1 and why in call.args[2]
    assert "unreadable state" in check_lifecycle_blocked(paths).detail


def test_the_dry_run_reports_the_same_exclusion(box) -> None:
    paths, _kind, record = box
    _m, _r, excluded = apply_projects(paths)
    dry = [line.text for line in check_upgrade(paths)]
    [line] = [line for line in dry if line.startswith(f"{P}:")]
    assert "will be left as is" in line and excluded.unreadable[P] in line
    assert not any(line.startswith(f"{OTHER}:") and "left as is" in line for line in dry)


def test_the_named_redeploy_is_accepted_once_the_record_is_removed(box) -> None:
    paths, _kind, record = box
    record.unlink()
    with docker_off():
        assert run_deploy(P, paths, redeploy=True) == 0
