# SPDX-License-Identifier: Apache-2.0
"""`boxmunge security resume` fails closed (audit B-02) and lifts safely."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from boxmunge.commands import security_resume, security_scan_core, security_scan_inputs
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scanner import (
    AttackVector,
    Finding,
    ScannerError,
    ScanResult,
    Severity,
    VulnStatus,
)
from boxmunge.paths import BoxPaths

_CRIT = Finding(
    cve_id="CVE-2026-0001", severity=Severity.CRITICAL, package="openssl",
    installed_version="1", fixed_version=None, title="", primary_url=None,
    attack_vector=AttackVector.NETWORK, status=VulnStatus.AFFECTED,
    vendor_severities={"debian": Severity.CRITICAL},
)


def _sr(ref: str, findings=()) -> ScanResult:
    return ScanResult(ref, tuple(findings), datetime.now(timezone.utc), None)


def make_paths(tmp_path, services=("web", "worker"), images=None) -> BoxPaths:
    """A registered, quarantined project 'demo' with the given services.

    ``images`` maps service → compose image; a service missing from it is
    build-only. Default: every service declares ``demo-<svc>:1``.
    """
    paths = BoxPaths(root=tmp_path)
    for d in (paths.state, paths.deploy_state, paths.caddy_sites, paths.config):
        d.mkdir(parents=True, exist_ok=True)
    images = images if images is not None else {s: f"demo-{s}:1" for s in services}
    proj = paths.projects / "demo"
    proj.mkdir(parents=True)
    (proj / "manifest.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "source": "bundle",
        "project": "demo", "hosts": ["demo.example.com"],
        "services": {s: {"port": 3000, "routes": [{"path": "/"}], "smoke": "x.sh"}
                     for s in services},
    }))
    compose_services = {
        s: ({"image": images[s]} if s in images else {"build": "."}) for s in services
    }
    (proj / "compose.yml").write_text(yaml.safe_dump({"services": compose_services}))
    (paths.state / "projects.txt").write_text("demo\n")
    expired = datetime(2025, 1, 1, tzinfo=timezone.utc)
    paths.cve_grace_state.write_text(json.dumps({
        "installed_at": expired.isoformat(),
        "expires_at": (expired + timedelta(hours=24)).isoformat(),
        "heads_up_sent": True,
    }))
    qfile = paths.project_quarantine_state("demo")
    qfile.write_text(json.dumps({
        "quarantined_at": "2026-10-01T03:00:00+00:00", "cve_id": "CVE-2026-0001",
        "severity": "Critical", "effective_severity": "Critical",
        "explanation": "test", "image_ref": "demo-web:1",
    }))
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
        lambda ref, timeout: _sr(ref, [_CRIT] if "web" in ref else []),
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
