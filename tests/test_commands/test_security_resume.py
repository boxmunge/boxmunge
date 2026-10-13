# SPDX-License-Identifier: Apache-2.0
"""`boxmunge security resume` fails closed (audit B-02) and lifts safely."""
from __future__ import annotations

import pytest

from boxmunge.commands import security_resume, security_scan_core, security_scan_inputs
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scanner import ScannerError
from tests.test_commands.cve_helpers import CRIT, make_box, seed_quarantine
from tests.test_commands.cve_helpers import scan_result as _sr


def make_paths(tmp_path, services=("web", "worker"), images=None):
    """A quarantined project 'demo' with the given services."""
    paths = make_box(tmp_path, services=services, images=images)
    seed_quarantine(paths)
    return paths


@pytest.fixture
def lift(monkeypatch):
    """Stub the lift primitives; record whether the lift ran."""
    calls: list[str] = []
    monkeypatch.setattr(security_resume, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_inputs, "container_image_digest", lambda c: None)
    monkeypatch.setattr(security_resume, "prepare_caddy_config", lambda p, m: None)
    monkeypatch.setattr(
        security_resume, "prepare_compose_override", lambda p, m, component=None: None,
    )
    monkeypatch.setattr(security_resume, "run_smoke", lambda p, paths_: (True, "ok"))
    monkeypatch.setattr(
        security_resume, "lift_quarantine", lambda *a, **k: calls.append("lift"),
    )
    return calls


def test_resume_refuses_when_one_image_fails_to_scan(tmp_path, monkeypatch, lift, capsys):
    """Audit B-02 script B: web errors, worker is clean → quarantine stays."""
    paths = make_paths(tmp_path)

    def flaky(ref, timeout):
        if "web" in ref:
            raise ScannerError("registry unreachable")
        return _sr(ref)

    monkeypatch.setattr(security_scan_core, "scan_image", flaky)
    rc = cmd_security_resume(["demo"], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert lift == []
    assert is_quarantined("demo", paths)
    assert "did not cover every image" in err
    assert "demo-web:1: scan failed" in err


def test_resume_refuses_when_budget_skips_an_image(tmp_path, monkeypatch, lift, capsys):
    paths = make_paths(tmp_path)
    monkeypatch.setattr(security_scan_core, "_PROJECT_BUDGET_SECONDS", 0)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: _sr(ref))
    rc = cmd_security_resume(["demo"], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert lift == []
    assert "skipped (scan budget exhausted)" in err


def test_resume_refuses_when_a_service_image_is_unidentifiable(
    tmp_path, monkeypatch, lift, capsys,
):
    """worker is build-only with no container digest: nothing to scan."""
    paths = make_paths(tmp_path, images={"web": "demo-web:1"})
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: _sr(ref))
    rc = cmd_security_resume(["demo"], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert lift == []
    assert "service 'worker': no image could be identified" in err


def test_resume_refuses_when_no_image_is_identifiable(tmp_path, monkeypatch, lift, capsys):
    paths = make_paths(tmp_path, services=("web",), images={})
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: _sr(ref))
    rc = cmd_security_resume(["demo"], paths)
    assert rc == 1
    assert lift == []
    assert "Re-scan: clear" not in capsys.readouterr().out


def test_resume_refuses_when_every_image_fails(tmp_path, monkeypatch, lift, capsys):
    paths = make_paths(tmp_path)

    def boom(ref, timeout):
        raise ScannerError("db download failed")

    monkeypatch.setattr(security_scan_core, "scan_image", boom)
    rc = cmd_security_resume(["demo"], paths)
    err = capsys.readouterr().err
    assert rc == 1
    assert lift == []
    assert "quarantine stays in place" in err


def test_resume_refuses_while_finding_still_quarantines(tmp_path, monkeypatch, lift, capsys):
    paths = make_paths(tmp_path)
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: _sr(ref, [CRIT] if "web" in ref else []),
    )
    rc = cmd_security_resume(["demo"], paths)
    assert rc == 1
    assert lift == []
    assert "CVE-2026-0001 (Critical) would still quarantine" in capsys.readouterr().err


def test_resume_lifts_after_complete_clean_rescan(tmp_path, monkeypatch, lift, capsys):
    paths = make_paths(tmp_path)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: _sr(ref))
    rc = cmd_security_resume(["demo"], paths)
    assert rc == 0
    assert lift == ["lift"]
    assert "every image scanned" in capsys.readouterr().out
