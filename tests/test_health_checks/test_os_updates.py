"""The auto-updates health check reports evidence, not just "enabled"."""
from __future__ import annotations

import inspect

from boxmunge.health_checks import os_updates as check_module
from boxmunge.os_updates import OsUpdateStatus, Problem


def test_problems_warn_with_their_hints(monkeypatch):
    status = OsUpdateStatus(problems=(
        Problem("stamp:stale", "package lists last refreshed successfully 3d 0h ago",
                "as root, `apt-get update` shows the failing source"),))
    monkeypatch.setattr(check_module, "inspect_os_updates", lambda: status)
    result = check_module.check_os_updates()
    assert (result.name, result.status) == ("auto-updates", "warn")
    assert "OS updates may not be installing" in result.detail
    assert "`apt-get update` shows the failing source" in result.detail


def test_evidence_of_health_is_ok(monkeypatch):
    from datetime import timedelta
    status = OsUpdateStatus(problems=(), stamp_age=timedelta(hours=5))
    monkeypatch.setattr(check_module, "inspect_os_updates", lambda: status)
    result = check_module.check_os_updates()
    assert result.status == "ok"
    assert "package lists refreshed 5h ago" in result.detail


def test_health_report_uses_the_evidence_check():
    from boxmunge.commands import health_cmd
    source = inspect.getsource(health_cmd.collect_health)
    assert "check_os_updates" in source
    assert "check_unattended_upgrades" not in source
