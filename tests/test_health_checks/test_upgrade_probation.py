# SPDX-License-Identifier: Apache-2.0
"""The upgrade-probation health check: a probation the health timer should
have promoted, but did not, is reported (#119)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.health_checks.upgrade_probation import check_upgrade_probation

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def box(paths):
    paths.upgrade_state.mkdir(parents=True)
    return paths


def _probation(paths, expires_at, version="1.4.0"):
    paths.probation.write_text(json.dumps({
        "version": version, "previous_slot": "b",
        "started_at": "2026-11-09T00:00:00+00:00", "expires_at": expires_at}))


def test_ok_without_a_probation(box):
    check = check_upgrade_probation(box, now=NOW)
    assert (check.name, check.status) == ("upgrade-probation", "ok")


def test_ok_while_on_probation(box):
    _probation(box, (NOW + timedelta(hours=2)).isoformat())
    check = check_upgrade_probation(box, now=NOW)
    assert check.status == "ok"
    assert "1.4.0" in check.detail and "2026-11-09 14:00 UTC" in check.detail


def test_ok_just_after_expiry_while_the_timer_catches_up(box):
    _probation(box, (NOW - timedelta(minutes=10)).isoformat())
    assert check_upgrade_probation(box, now=NOW).status == "ok"


def test_warns_when_expired_and_not_promoted(box):
    _probation(box, (NOW - timedelta(hours=75, minutes=20)).isoformat())
    check = check_upgrade_probation(box, now=NOW)
    assert check.status == "warn"
    assert "expired 75 h ago and was not promoted" in check.detail
    assert f"sudo {box.bin / 'boxmunge-upgrade'} check-probation" in check.detail
    assert f"sudo rm {box.probation}" in check.detail


def test_never_errors_so_probation_cannot_roll_back_on_it(box):
    """check-probation rolls back when health exits 2: this check only warns."""
    box.probation.write_text("{not json")
    check = check_upgrade_probation(box, now=NOW)
    assert check.status == "warn"
    assert str(box.probation) in check.detail


def test_warns_on_a_marker_without_a_usable_expiry(box):
    _probation(box, "tomorrow")
    check = check_upgrade_probation(box, now=NOW)
    assert check.status == "warn" and "expires_at" in check.detail


def test_is_part_of_health():
    import inspect

    from boxmunge.commands import health_cmd
    assert "check_upgrade_probation" in inspect.getsource(health_cmd.collect_health)
