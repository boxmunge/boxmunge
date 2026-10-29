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


def test_unwritable_scans_dir_is_a_write_failure_not_a_failed_scan(
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
    assert priority == 1
    assert "no result is recorded" in body
    assert "not covered" not in body
    assert not [s for s in pushover.sent if "CVE scan incomplete" in s[0]]


def test_the_alert_names_the_last_recorded_result(tmp_path, monkeypatch):
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    when = datetime(2026, 10, 28, 3, 0, tzinfo=timezone.utc)
    write_scan_state(paths.project_scan_state("demo"), decisions=(), scanned_at=when)
    _unwritable_scans(paths)
    assert cmd_security_scan(["demo"], paths) == 1
    [(_, body, priority)] = _unrecorded_alerts(pushover)
    assert priority == 1
    assert f"last recorded result (at {when.isoformat()})" in body
    assert "coverage is unchanged" not in body


def test_a_kev_found_by_a_run_whose_write_fails_is_still_enforced_and_alerted(
    tmp_path, monkeypatch,
):
    from boxmunge.cve.kev import KevCatalog
    from boxmunge.cve.quarantine import is_quarantined
    from tests.test_commands.cve_helpers import Docker, finding
    paths = make_box(tmp_path)
    pushover = Pushover(monkeypatch, paths)
    Docker(monkeypatch)
    cve = "CVE-2026-13221"
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, [finding(cve)]))
    kev = KevCatalog(frozenset({cve}), datetime.now(timezone.utc))
    monkeypatch.setattr(security_actions, "load_kev", lambda p: kev)
    monkeypatch.setattr(security_actions, "refresh_kev", lambda p: type("R", (), {"rejected": None})())
    _unwritable_scans(paths)

    assert cmd_security_scan([], paths) == 1

    assert is_quarantined("demo", paths)
    assert any("QUARANTINED" in t for t in pushover.titles())
    assert _unrecorded_alerts(pushover)


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


def _register(paths, name, *, state=False):
    with (paths.state / "projects.txt").open("a") as f:
        f.write(f"{name}\n")
    if state:
        write_scan_state(paths.project_scan_state(name), decisions=())


def test_fleet_scan_reports_an_unfinished_removal_once_and_without_failing(
    tmp_path, monkeypatch, capsys,
):
    paths = make_box(tmp_path, projects=("aaa",))
    pushover = Pushover(monkeypatch, paths)
    _register(paths, "gone", state=True)

    rc = cmd_security_scan([], paths)

    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("registered but missing, so not scanned: gone") == 1
    assert "sudo boxmunge-server project-forget <name>" in out
    assert "Manifest not found" not in out
    assert pushover.sent == []


def test_a_never_deployed_name_is_silent_and_does_not_fail(tmp_path, monkeypatch, capsys, caplog):
    paths = make_box(tmp_path, projects=("aaa",))
    pushover = Pushover(monkeypatch, paths)
    _register(paths, "pending")
    assert cmd_security_scan([], paths) == 0
    assert "pending" not in capsys.readouterr().out
    assert "pending" not in caplog.text and pushover.sent == []
    assert cmd_security_scan(["pending"], paths) == 0
    assert "awaiting its first deploy" in capsys.readouterr().out


def test_scan_of_an_unfinished_removal_names_the_forget_command(tmp_path, capsys):
    paths = make_box(tmp_path, projects=("aaa",))
    _register(paths, "gone", state=True)
    assert cmd_security_scan(["gone"], paths) == 1
    err = capsys.readouterr().err
    assert "gone was deployed and its project directory is gone" in err
    assert "project-forget gone" in err


def test_a_missing_directory_with_containers_fails_the_run(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    paths = make_box(tmp_path, projects=("aaa",))
    Pushover(monkeypatch, paths)
    _register(paths, "gone")
    monkeypatch.setattr("boxmunge.docker_containers.project_containers",
                        lambda p: [SimpleNamespace(name="gone-web-1")] if p == "gone" else [])
    assert cmd_security_scan([], paths) == 1
    out = capsys.readouterr().out
    assert "gone: ERROR — no project directory, but containers still exist (gone-web-1)" in out


def test_an_enforcement_error_is_not_masked_by_a_write_failure():
    import pytest as _p
    from boxmunge.commands.security_enforce import raise_enforcement_error
    with _p.raises(RuntimeError) as exc:
        raise_enforcement_error("quarantine failed", "could not record the result")
    assert "quarantine failed" in str(exc.value) and "could not record" in str(exc.value)
