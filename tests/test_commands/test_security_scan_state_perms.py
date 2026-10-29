# SPDX-License-Identifier: Apache-2.0
"""A manual scan whose result cannot be written says so, plainly; registry
entries with no project directory are reported as such, not as scan failures;
resume and the quarantine gate never write scan state."""
from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from boxmunge.commands import security_actions, security_resume, security_scan_core
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.cve.scan_state import write_scan_state
from tests.test_commands.cve_helpers import Pushover, make_box, scan_result, seed_quarantine

pytestmark = pytest.mark.skipif(os.getuid() == 0, reason="root can write a 0555 directory")


@pytest.fixture(autouse=True)
def trivy(monkeypatch):
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_resume, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: scan_result(ref))


def _unwritable_scans(paths) -> None:
    """state/scans as v0.6-v0.9.2 left it on a root-run scan."""
    scans = paths.state / "scans"
    scans.mkdir(exist_ok=True)
    scans.chmod(0o555)


def _unrecorded_alerts(pushover):
    return [s for s in pushover.sent if "result not recorded" in s[0]]


def test_unwritable_scans_dir_is_a_write_failure_not_an_uncovered_project(
    tmp_path, monkeypatch, capsys,
):
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    _unwritable_scans(paths)

    rc = cmd_security_scan(["demo"], paths)

    out = capsys.readouterr().out
    assert rc == 1  # still fails noisily
    assert "scanned, but could not record the result" in out
    assert f"sudo chown -R deploy:deploy {paths.state / 'scans'}" in out
    [(title, body, priority)] = _unrecorded_alerts(pushover)
    assert "not covered by CVE quarantine" in body  # never scanned: really uncovered
    assert priority == 1
    assert not [s for s in pushover.sent if "CVE scan incomplete" in s[0]]


def test_a_current_scan_result_keeps_its_coverage_in_the_alert(tmp_path, monkeypatch):
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    write_scan_state(paths.project_scan_state("demo"), decisions=(),
                     scanned_at=datetime.now(timezone.utc))
    _unwritable_scans(paths)

    assert cmd_security_scan(["demo"], paths) == 1

    [(_, body, priority)] = _unrecorded_alerts(pushover)
    assert "not covered" not in body
    assert "keep their last successful scan" in body and "coverage is unchanged" in body
    assert priority == 0


def test_a_stale_scan_result_is_not_called_current(tmp_path, monkeypatch):
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    write_scan_state(paths.project_scan_state("demo"), decisions=(),
                     scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    _unwritable_scans(paths)
    cmd_security_scan(["demo"], paths)
    [(_, body, _)] = _unrecorded_alerts(pushover)
    assert "not covered by CVE quarantine" in body


def test_resume_does_not_write_scan_state(tmp_path, monkeypatch):
    """The lift's re-scan is audit-only, so an unwritable state/scans is no obstacle."""
    paths = make_box(tmp_path)
    seed_quarantine(paths)
    _unwritable_scans(paths)
    lifted: list[str] = []
    monkeypatch.setattr(security_resume, "prepare_caddy_config", lambda p, m: None)
    monkeypatch.setattr(security_resume, "prepare_compose_override", lambda p, m, component=None: None)
    monkeypatch.setattr(security_resume, "run_smoke", lambda p, paths_: (True, "ok"))
    monkeypatch.setattr(security_resume, "lift_quarantine", lambda *a, **k: lifted.append("lift"))
    assert cmd_security_resume(["demo"], paths) == 0
    assert lifted == ["lift"]
    assert list((paths.state / "scans").iterdir()) == []


def test_the_quarantine_gate_does_not_write_scan_state():
    import inspect
    from boxmunge.commands import quarantine_gate
    assert "write_scan_state" not in inspect.getsource(quarantine_gate)
    assert "scan_one_project" not in inspect.getsource(quarantine_gate)


def test_fleet_scan_reports_a_missing_project_once_and_without_failing(
    tmp_path, monkeypatch, capsys,
):
    paths = make_box(tmp_path, projects=("aaa",))
    pushover = Pushover(monkeypatch, paths)
    with (paths.state / "projects.txt").open("a") as f:
        f.write("gone\n")
    (paths.state / "gone.lock").write_text("")

    rc = cmd_security_scan([], paths)

    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("registered but missing, so not scanned: gone") == 1
    assert "sudo boxmunge-server project-forget <name>" in out
    assert "Manifest not found" not in out
    assert pushover.sent == []


def test_scan_of_a_missing_project_names_the_forget_command(tmp_path, capsys):
    paths = make_box(tmp_path, projects=("aaa",))
    with (paths.state / "projects.txt").open("a") as f:
        f.write("gone\n")
    assert cmd_security_scan(["gone"], paths) == 1
    err = capsys.readouterr().err
    assert "gone is registered but has no project directory" in err
    assert "project-forget gone" in err
