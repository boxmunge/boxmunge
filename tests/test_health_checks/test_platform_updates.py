# SPDX-License-Identifier: Apache-2.0
"""The platform-updates health check."""
from __future__ import annotations

import json

import pytest

from boxmunge.health_checks.platform_updates import check_platform_updates
from boxmunge.version import write_installed_version

GH = "https://github.com/boxmunge/boxmunge/releases/tag/v"


def _write(paths, blocked, current="0.10.3"):
    paths.platform_update_state.write_text(json.dumps({
        "checked_at": "2026-10-01T12:00:00+00:00", "current_version": current,
        "blocked": blocked, "alerted": None}))


def _blocked(version="0.11.2", cls="security", reason=None):
    return {"version": version, "url": f"{GH}{version}", "class": cls,
            "reason": reason or {"breaking_release": "0.11.0"}}


@pytest.fixture
def box(paths):
    write_installed_version(paths, "0.10.3", "abc1234")
    return paths


def test_ok_before_any_recorded_check(box):
    check = check_platform_updates(box)
    assert (check.name, check.status) == ("platform-updates", "ok")


def test_ok_when_nothing_blocked(box):
    _write(box, None)
    assert check_platform_updates(box).status == "ok"


def test_warns_naming_version_and_breaking_release(box):
    _write(box, _blocked())
    check = check_platform_updates(box)
    assert check.status == "warn"
    assert "Security release 0.11.2" in check.detail
    assert "0.11.0" in check.detail and "breaking" in check.detail
    assert "upgrade" in check.detail


def test_warns_naming_major_version(box):
    _write(box, _blocked("1.0.1", cls="breakfix", reason={"major": 1}))
    check = check_platform_updates(box)
    assert check.status == "warn"
    assert "Break-fix release 1.0.1" in check.detail
    assert "major version 1" in check.detail


def test_never_error(box):
    """health exits 2 on error, which rolls back an upgrade on probation."""
    _write(box, _blocked())
    assert check_platform_updates(box).status != "error"
    box.platform_update_state.write_text("{broken")
    assert check_platform_updates(box).status == "warn"


def test_ok_once_the_blocked_release_is_installed(box):
    _write(box, _blocked())
    write_installed_version(box, "0.11.2", "def5678")
    check = check_platform_updates(box)
    assert check.status == "ok"
    assert "0.11.2" in check.detail


def test_unreadable_state_warns_with_the_reason(box):
    box.platform_update_state.write_text("{broken")
    check = check_platform_updates(box)
    assert check.status == "warn"
    assert "platform-updates.json" in check.detail


def test_health_reports_it_and_exits_warn_not_error(box, capsys):
    """Every other check stubbed ok: a blocked release makes `health` exit 1."""
    from contextlib import ExitStack
    from unittest.mock import patch

    from boxmunge.commands import health_cmd
    from boxmunge.commands.health_cmd import HealthCheck, run_health
    from boxmunge.health_checks import container_updates, hardening, security, sshd

    ok = HealthCheck("stub", "ok", "")
    _write(box, _blocked())
    with ExitStack() as stack:
        for module in (health_cmd, container_updates, hardening, security, sshd):
            for name in dir(module):
                if name.startswith("check_"):
                    stack.enter_context(patch.object(module, name, return_value=ok))
        code = run_health(box, as_json=True)
    report = json.loads(capsys.readouterr().out)
    checks = {c["name"]: c for c in report["checks"]}
    assert checks["platform-updates"]["status"] == "warn"
    assert code == 1
