"""The system-container health check is an error, not a warning: there is no
host fallback, so backups fail while it fails."""

import boxmunge.system_container as sc
from boxmunge.commands.health_cmd import check_system_container


def test_ok_when_running_and_mounted(paths, system_container) -> None:
    assert check_system_container(paths).status == "ok"


def test_error_with_remediation_when_missing(paths, monkeypatch) -> None:
    monkeypatch.setattr(sc, "_inspect", lambda name: None)
    check = check_system_container(paths)
    assert check.status == "error"
    assert "up -d --build" in check.detail
    assert "fallback active" not in check.detail


def test_missing_then_running_is_ok(paths, system_container, monkeypatch) -> None:
    """An upgrade recreating it: one missing probe is re-probed, not an error."""
    from boxmunge.commands import health_cmd
    real, answers, slept = sc._inspect, [None], []
    monkeypatch.setattr(sc, "_inspect", lambda name: answers.pop(0) if answers else real(name))
    monkeypatch.setattr(health_cmd, "REPROBE_DELAY", 5.0)
    monkeypatch.setattr(health_cmd.time, "sleep", slept.append)
    assert check_system_container(paths).status == "ok"
    assert slept == [5.0]


def test_missing_twice_is_an_error(paths, monkeypatch) -> None:
    from boxmunge.commands import health_cmd
    calls, slept = [], []
    monkeypatch.setattr(sc, "_inspect", lambda name: calls.append(name))
    monkeypatch.setattr(health_cmd, "REPROBE_DELAY", 5.0)
    monkeypatch.setattr(health_cmd.time, "sleep", slept.append)
    assert check_system_container(paths).status == "error"
    assert len(calls) == 2 and slept == [5.0]
