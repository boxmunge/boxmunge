# SPDX-License-Identifier: Apache-2.0
"""A 0.10.1-stage detection that cannot tell (legacy_stage raises OSError)
is never read as "no stage": every consumer holds or reports, none crashes
and none acts as if production's files were in the project directory."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from boxmunge.backup_source import backup_source
from boxmunge.commands.check import _check_one
from boxmunge.commands.legacy_stage_cmd import legacy_stage_locked
from boxmunge.commands.security_enforce import enforce
from boxmunge.commands.upgrade_steps import check_upgrade
from boxmunge.upgrade_exclusions import Exclusions, apply_projects, notify_exclusions
from tests.bundle_helpers import tree_snapshot

CANNOT_TELL = "cannot tell whether a 0.10.1 stage is on disk for 'myapp'"


def _undetectable(module: str):
    return patch(f"{module}.legacy_stage", side_effect=PermissionError(13, "denied"))


def _deployed(paths) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.stage_helpers import V1
    from tests.txn_helpers import docker_off
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0


def test_check_runs_no_smoke_and_warns(paths, capsys) -> None:
    with _undetectable("boxmunge.commands.check"), \
            patch("boxmunge.commands.check.run_check") as smoke, \
            patch("boxmunge.commands.check.update_health_state") as health:
        assert _check_one("myapp", paths, read_only=False) == 1
    smoke.assert_not_called()
    assert health.call_args.args[:2] == ("myapp", 1)
    assert CANNOT_TELL in health.call_args.args[2]
    assert CANNOT_TELL in capsys.readouterr().out


def test_read_only_check_records_nothing(paths) -> None:
    with _undetectable("boxmunge.commands.check"), \
            patch("boxmunge.commands.check.update_health_state") as health:
        assert _check_one("myapp", paths, read_only=True) == 1
    health.assert_not_called()


def test_backup_is_skipped_with_an_alert(paths) -> None:
    with _undetectable("boxmunge.backup_source"):
        source = backup_source(paths, "myapp")
    assert source.manifest is None and source.alert
    assert CANNOT_TELL in source.skip


def test_a_due_quarantine_is_not_taken(paths) -> None:
    with _undetectable("boxmunge.commands.security_enforce"), \
            patch("boxmunge.commands.security_enforce.quarantine_project") as take:
        outcome = enforce(paths, "myapp", hosts=[], compose_files=[],
                          headline=object(), in_grace=False)
    take.assert_not_called()
    assert outcome.error is not None and CANNOT_TELL in outcome.error


def test_nothing_due_is_not_an_error(paths) -> None:
    with _undetectable("boxmunge.commands.security_enforce"):
        assert enforce(paths, "myapp", hosts=[], compose_files=[],
                       headline=None, in_grace=False).error is None
        assert enforce(paths, "myapp", hosts=[], compose_files=[],
                       headline=object(), in_grace=True).error is None


def test_upgrade_leaves_the_project_as_is_and_alerts(paths) -> None:
    _deployed(paths)
    before = tree_snapshot(paths.project_dir("myapp"))
    with _undetectable("boxmunge.commands.upgrade_steps"):
        _m, regen, excluded = apply_projects(paths)
        dry = check_upgrade(paths)
    assert regen.processed == [] and tree_snapshot(paths.project_dir("myapp")) == before
    assert "myapp" in excluded.names() and CANNOT_TELL in excluded.undetermined["myapp"]
    assert any(CANNOT_TELL in line and "left as is" in line for line in dry)
    with patch("boxmunge.upgrade_exclusions.notify") as summary:
        notify_exclusions(paths, excluded)
    assert summary.call_args.kwargs["priority"] == 1
    assert f"- myapp: {CANNOT_TELL}" in summary.call_args.args[2]


def test_no_undetermined_project_sends_no_summary(paths) -> None:
    with patch("boxmunge.upgrade_exclusions.notify") as summary:
        notify_exclusions(paths, Exclusions())
    summary.assert_not_called()


def test_legacy_stage_command_refuses(paths, capsys) -> None:
    with _undetectable("boxmunge.commands.legacy_stage_cmd"):
        assert legacy_stage_locked(paths, "myapp", None, False) == 1
    assert CANNOT_TELL in capsys.readouterr().err


# -- D fix wave ---------------------------------------------------------------

RETRY = "fix the permissions (or the error shown), then retry"


def test_every_consumer_says_what_to_do(paths, capsys) -> None:
    with _undetectable("boxmunge.commands.check"), \
            patch("boxmunge.commands.check.update_health_state") as health:
        _check_one("myapp", paths, read_only=False)
    assert RETRY in health.call_args.args[2]
    with _undetectable("boxmunge.backup_source"):
        assert RETRY in backup_source(paths, "myapp").skip
    with _undetectable("boxmunge.commands.security_enforce"):
        assert RETRY in enforce(paths, "myapp", hosts=[], compose_files=[],
                                headline=object(), in_grace=False).error
    with _undetectable("boxmunge.commands.legacy_stage_cmd"):
        legacy_stage_locked(paths, "myapp", None, False)
    assert RETRY in capsys.readouterr().err


UPGRADE_ADVICE = ("it keeps its previous configs: fix the cause, then deploy, "
                  "resume or recover myapp. If a 0.10.1 stage turns out to exist, "
                  "boxmunge-server legacy-stage myapp resolves it")


def test_the_upgrade_says_what_to_do_for_the_named_project(paths) -> None:
    _deployed(paths)
    with _undetectable("boxmunge.commands.upgrade_steps"):
        _m, _r, excluded = apply_projects(paths)
        dry = check_upgrade(paths)
    assert any(UPGRADE_ADVICE in line for line in dry)
    with patch("boxmunge.upgrade_exclusions.notify") as summary:
        notify_exclusions(paths, excluded)
    body = summary.call_args.args[2]
    assert f"- myapp: {CANNOT_TELL}" in body and UPGRADE_ADVICE in body
    assert "<project>" not in body and "then retry" not in body


def _quarantined(paths) -> None:
    record = paths.project_quarantine_state("myapp")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text('{"cve_id": "CVE-2026-0001"}\n')


def test_a_quarantine_is_not_reasserted_when_it_cannot_tell(paths) -> None:
    _quarantined(paths)
    with _undetectable("boxmunge.commands.security_enforce"), \
            patch("boxmunge.commands.security_enforce.reassert_quarantine") as reassert:
        outcome = enforce(paths, "myapp", hosts=[], compose_files=[],
                          headline=None, in_grace=True)
    reassert.assert_not_called()
    assert outcome.error is not None and CANNOT_TELL in outcome.error


def test_an_unreadable_quarantine_record_does_not_escape_enforce(paths) -> None:
    with _undetectable("boxmunge.commands.security_enforce"), \
            patch("boxmunge.commands.security_enforce.is_quarantined",
                  side_effect=PermissionError(13, "record denied")):
        outcome = enforce(paths, "myapp", hosts=[], compose_files=[],
                          headline=None, in_grace=False)
    assert outcome.error is not None and CANNOT_TELL in outcome.error
    assert "record denied" in outcome.error


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads through mode 000")
def test_a_real_permission_error_reaches_the_dry_run(paths) -> None:
    """No patch: an unsearchable state/staging/ makes the detection raise
    EACCES, which the dry run reports instead of crashing or reading "no stage"."""
    _deployed(paths)
    staging = paths.state / "staging"
    staging.mkdir(exist_ok=True)
    staging.chmod(0)
    try:
        dry = check_upgrade(paths)
    finally:
        staging.chmod(0o755)
    assert any(CANNOT_TELL in line and "Permission denied" in line and "left as is" in line
               for line in dry)
