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
