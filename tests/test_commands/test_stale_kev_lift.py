# SPDX-License-Identifier: Apache-2.0
"""A stale CISA KEV catalog never lifts a quarantine that rests on it.

A stale catalog reads as "nothing is exploited", so under balanced (where
only KEV quarantines) every finding looks harmless. The scan's own lift
already refused that; `security resume` and the quarantine deploy gate
lifted the same KEV-listed, unpatched image. All three now share one rule
(cve.lift_rule). A strict quarantine taken for a non-KEV finding is judged
on severity, which a stale catalog does not hide, so it still lifts.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from boxmunge.commands import quarantine_gate as gate
from boxmunge.commands import quarantine_lift, security_resume, security_scan_core
from boxmunge.commands.deploy_images import candidate_name
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.lift_rule import stale_kev_lift_refusal
from boxmunge.cve.policy import Posture
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.docker_containers import LocalImage
from boxmunge.release_target import production_target
from tests.test_commands.cve_helpers import (
    CRIT, Docker, finding, make_box, render_site, scan_result, seed_quarantine,
)

KEV_CVE = CRIT.cve_id  # the CVE seed_quarantine records
OTHER_CVE = "CVE-2026-9999"
TODAY = date(2026, 11, 9)


def _write_kev(paths, *cves: str, age_days: int) -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    fetched = datetime.now(timezone.utc) - timedelta(days=age_days)
    paths.kev_catalog.write_text(json.dumps({
        "fetched_at": fetched.isoformat(), "cve_ids": list(cves)}))


def _catalog(*cves: str, age_days: int | None) -> KevCatalog:
    fetched = (None if age_days is None else
               datetime(2026, 11, 9, tzinfo=timezone.utc) - timedelta(days=age_days))
    return KevCatalog(frozenset(cves), fetched)


class TestRule:
    @pytest.mark.parametrize("posture", list(Posture))
    def test_a_fresh_catalog_never_refuses(self, posture) -> None:
        kev = _catalog(KEV_CVE, age_days=1)
        assert stale_kev_lift_refusal(posture, KEV_CVE, kev, TODAY) is None

    @pytest.mark.parametrize("posture", [Posture.BALANCED, Posture.RELAXED])
    @pytest.mark.parametrize("age", [20, None])
    def test_kev_only_postures_refuse_on_a_stale_or_missing_catalog(self, posture, age) -> None:
        refusal = stale_kev_lift_refusal(posture, OTHER_CVE, _catalog(age_days=age), TODAY)
        assert refusal is not None
        assert "boxmunge security scan" in refusal
        assert ("stale" in refusal) if age else ("no CISA KEV catalog" in refusal)

    @pytest.mark.parametrize("posture", [Posture.STRICT, Posture.PARANOID])
    def test_strict_refuses_when_the_recorded_cve_is_on_the_cached_catalog(self, posture) -> None:
        kev = _catalog(KEV_CVE, age_days=20)
        assert stale_kev_lift_refusal(posture, KEV_CVE, kev, TODAY) is not None

    @pytest.mark.parametrize("posture", [Posture.STRICT, Posture.PARANOID])
    def test_strict_non_kev_quarantine_is_unaffected(self, posture) -> None:
        kev = _catalog(KEV_CVE, age_days=20)
        assert stale_kev_lift_refusal(posture, OTHER_CVE, kev, TODAY) is None


# ---- security resume ----

def _resume_box(tmp_path, monkeypatch, security, findings):
    paths = make_box(tmp_path, security=security)
    seed_quarantine(paths)
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, findings))
    monkeypatch.setattr(security_resume, "refresh_db", lambda: None)
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                        lambda p, m, component=None: None)
    monkeypatch.setattr(quarantine_lift, "run_smoke", lambda p, paths_: (True, "ok"))
    paths.docker = Docker(monkeypatch)
    return paths


def test_resume_refuses_the_same_kev_image_on_a_stale_catalog(
        tmp_path, monkeypatch, capsys) -> None:
    paths = _resume_box(tmp_path, monkeypatch, {"posture": "balanced"}, [CRIT])
    _write_kev(paths, KEV_CVE, age_days=20)
    assert cmd_security_resume(["demo"], paths) == 1
    assert is_quarantined("demo", paths)
    err = capsys.readouterr().err
    assert "stale" in err and "boxmunge security scan" in err
    assert "stays in place" in err


def test_resume_refuses_on_a_missing_catalog(tmp_path, monkeypatch, capsys) -> None:
    paths = _resume_box(tmp_path, monkeypatch, {"posture": "balanced"}, [])
    assert cmd_security_resume(["demo"], paths) == 1
    assert is_quarantined("demo", paths)
    assert "no CISA KEV catalog" in capsys.readouterr().err


def test_resume_lifts_once_the_catalog_is_fresh(tmp_path, monkeypatch) -> None:
    paths = _resume_box(tmp_path, monkeypatch, {"posture": "balanced"}, [])
    _write_kev(paths, OTHER_CVE, age_days=0)
    assert cmd_security_resume(["demo"], paths) == 0
    assert not is_quarantined("demo", paths)


def test_resume_of_a_strict_non_kev_quarantine_ignores_staleness(
        tmp_path, monkeypatch) -> None:
    paths = _resume_box(tmp_path, monkeypatch, None, [])  # strict, fixed image
    _write_kev(paths, OTHER_CVE, age_days=20)
    assert cmd_security_resume(["demo"], paths) == 0
    assert not is_quarantined("demo", paths)


# ---- the deploy gate ----

def _manifest(security=None):
    m = {"project": "demo", "hosts": ["demo.example.com"], "services": {}}
    if security is not None:
        m["security"] = security
    return m


@pytest.fixture
def gate_box(tmp_path, monkeypatch):
    paths = make_box(tmp_path)
    seed_quarantine(paths)
    web = "sha256:" + "a" * 64
    images = {candidate_name("demo", "web"): LocalImage(web, ()),
              "boxmunge.invalid/demo/web": LocalImage(web, ())}
    services = {"web": {"image": candidate_name("demo", "web")}}
    monkeypatch.setattr(gate, "resolved_services", lambda target: ({}, services))
    monkeypatch.setattr(gate.docker_containers, "local_image", images.get)
    monkeypatch.setattr(gate, "resolve_deployed_config",
                        lambda *a, **k: {"services": {"web": {"read_only": True}}})
    monkeypatch.setattr(gate, "refresh_db", lambda: None)
    paths.scan_findings = []
    monkeypatch.setattr("boxmunge.commands.security_scan_core.scan_image",
                        lambda ref, timeout=None: scan_result(ref, paths.scan_findings))
    return paths


def test_gate_refuses_the_same_kev_image_on_a_stale_catalog(gate_box, capsys) -> None:
    gate_box.scan_findings = [finding(KEV_CVE)]
    _write_kev(gate_box, KEV_CVE, age_days=20)
    with pytest.raises(gate.QuarantineRefused) as e:
        gate.clear_release(gate_box, production_target(gate_box, "demo"), _manifest())
    text = str(e.value)
    assert "stale" in text and "boxmunge security scan" in text
    assert "nothing was started" in text
    assert "Scan: clear" not in capsys.readouterr().out


def test_gate_clears_once_the_catalog_is_fresh(gate_box) -> None:
    _write_kev(gate_box, KEV_CVE, age_days=0)
    clearance = gate.clear_release(gate_box, production_target(gate_box, "demo"), _manifest())
    assert clearance.project == "demo"


def test_gate_of_a_strict_non_kev_quarantine_ignores_staleness(gate_box) -> None:
    seed_quarantine(gate_box, cve_id=OTHER_CVE)
    _write_kev(gate_box, KEV_CVE, age_days=20)
    clearance = gate.clear_release(gate_box, production_target(gate_box, "demo"),
                                   _manifest({"posture": "strict"}))
    assert clearance.cve_id == OTHER_CVE
