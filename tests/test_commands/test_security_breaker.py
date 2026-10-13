# SPDX-License-Identifier: Apache-2.0
"""The circuit breaker in the real fleet scan (Docker and Trivy stubbed)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from boxmunge.commands import security_actions, security_scan_core, security_scan_inputs
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.cve.breaker import read_held
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.shell import run_command
from tests.test_commands.cve_helpers import Docker, Pushover, finding, make_box, scan_result

_SHARED = "CVE-2026-13221"


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    """Three projects; every image carries the same quarantine-level CVE."""
    paths = make_box(tmp_path, projects=("aaa", "bbb", "ccc"))
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_inputs, "container_image_digest", lambda c: None)
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: scan_result(ref, [finding(_SHARED)]),
    )
    Docker(monkeypatch)
    return paths, Pushover(monkeypatch, paths)


def _breaker_alerts(pushover):
    return [s for s in pushover.sent if "Circuit breaker held" in s[0]]


def test_shared_cve_is_held_with_one_alert(fleet, capsys):
    paths, pushover = fleet
    assert cmd_security_scan([], paths) == 2
    assert not any(is_quarantined(p, paths) for p in ("aaa", "bbb", "ccc"))
    assert set(read_held(paths)) == {"aaa", "bbb", "ccc"}
    [(title, body, priority)] = _breaker_alerts(pushover)
    assert priority == 1 and "3 quarantines" in title
    assert f"{_SHARED}: aaa, bbb, ccc" in body
    assert "boxmunge security scan --apply-held" in body
    assert [t for t in pushover.titles() if "QUARANTINED" in t] == []
    assert "HELD by the circuit breaker" in capsys.readouterr().out


def test_hold_persists_without_re_alerting(fleet):
    paths, pushover = fleet
    cmd_security_scan([], paths)
    pushover.clear()
    assert cmd_security_scan([], paths) == 2
    assert set(read_held(paths)) == {"aaa", "bbb", "ccc"}
    assert pushover.sent == []


def test_undelivered_hold_alert_is_retried(fleet, monkeypatch):
    """A hold is recorded as alerted only once the alert was delivered."""
    paths, pushover = fleet
    monkeypatch.setattr("boxmunge.notify.send_notification", lambda *a, **k: False)
    cmd_security_scan([], paths)
    assert set(read_held(paths)) == {"aaa", "bbb", "ccc"}
    monkeypatch.setattr("boxmunge.notify.send_notification", pushover._send)
    cmd_security_scan([], paths)
    assert len(_breaker_alerts(pushover)) == 1
    pushover.clear()
    cmd_security_scan([], paths)
    assert _breaker_alerts(pushover) == []


def test_single_project_scan_keeps_a_held_project_held(fleet):
    paths, _ = fleet
    cmd_security_scan([], paths)
    assert cmd_security_scan(["aaa"], paths) == 2
    assert not is_quarantined("aaa", paths)
    assert set(read_held(paths)) == {"aaa", "bbb", "ccc"}


def test_apply_held_quarantines_and_clears(fleet):
    paths, pushover = fleet
    cmd_security_scan([], paths)
    pushover.clear()
    assert cmd_security_scan(["--apply-held"], paths) == 0
    assert all(is_quarantined(p, paths) for p in ("aaa", "bbb", "ccc"))
    assert read_held(paths) == {}
    assert len([t for t in pushover.titles() if "QUARANTINED" in t]) == 3


def test_kev_quarantines_are_not_held(fleet, monkeypatch):
    paths, pushover = fleet
    kev = KevCatalog(frozenset({_SHARED}), datetime.now(timezone.utc))
    monkeypatch.setattr(security_actions, "load_kev", lambda p: kev)
    assert cmd_security_scan([], paths) == 2
    assert all(is_quarantined(p, paths) for p in ("aaa", "bbb", "ccc"))
    assert read_held(paths) == {} and _breaker_alerts(pushover) == []


def test_one_project_quarantines_normally(tmp_path, monkeypatch):
    paths = make_box(tmp_path, projects=("aaa", "bbb", "ccc"))
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_inputs, "container_image_digest", lambda c: None)
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: scan_result(ref, [finding()] if ref.startswith("aaa") else []),
    )
    Docker(monkeypatch)
    pushover = Pushover(monkeypatch, paths)
    assert cmd_security_scan([], paths) == 2
    assert is_quarantined("aaa", paths) and not is_quarantined("bbb", paths)
    assert _breaker_alerts(pushover) == []


def test_corrupt_breaker_state_applies_nothing_new(fleet, capsys):
    paths, _ = fleet
    (paths.state / "cve-breaker.json").write_text("{broken")
    assert cmd_security_scan(["aaa"], paths) == 1
    assert not is_quarantined("aaa", paths)
    assert "no new quarantine was applied" in capsys.readouterr().err


def test_fleet_view_shows_held_projects(fleet, monkeypatch, capsys):
    import json

    from boxmunge.commands.security_cmd import cmd_security

    paths, _ = fleet
    cmd_security_scan([], paths)
    capsys.readouterr()
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: paths)
    cmd_security(["--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["held_by_breaker"] == {p: [_SHARED] for p in ("aaa", "bbb", "ccc")}
    assert payload["posture_distribution"]["paranoid"] == 0
    cmd_security([])
    assert "Held by the CVE circuit breaker (still running): 3" in capsys.readouterr().out


def test_apply_held_is_in_the_usage_and_help_text():
    from boxmunge.commands.help import HELP_TEXT
    from boxmunge.commands.security_cmd import USAGE
    from boxmunge.commands.usage import usage_for

    for text in (usage_for("security"), HELP_TEXT, USAGE):
        assert "security scan --apply-held" in text


def test_deploy_shell_refuses_apply_held(capsys):
    assert run_command("security", ["scan", "--apply-held"]) == 1
    assert "operator-only" in capsys.readouterr().err
