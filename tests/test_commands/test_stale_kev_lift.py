# SPDX-License-Identifier: Apache-2.0
"""What a stale or missing CISA KEV catalog does to the routes that lift a
quarantine (cve.lift_rule).

A stale catalog reads as "nothing is exploited". `security resume` and the
deploy gate used to lift the same KEV-listed, unpatched image on one. Now:
a stale catalog whose cached IDs list a CVE the re-scan finds in the images
refuses; one that lists none of them allows the lift with a priority-1
alert naming the gap; no usable catalog refuses under every posture. Every
refusal names the ways to fresh data and `security resume
--accept-stale-kev`, the audited override.
"""
from __future__ import annotations

import dataclasses
import json
from datetime import date, datetime, timedelta, timezone

import pytest

from boxmunge.commands import quarantine_gate as gate
from boxmunge.commands import quarantine_lift, security_resume, security_scan_core
from boxmunge.commands.deploy_images import candidate_name
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.lift_rule import check_kev_for_lift
from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision, Severity
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.docker_containers import LocalImage
from boxmunge.release_target import production_target
from tests.test_commands.cve_helpers import (
    CRIT, Docker, Pushover, finding, make_box, render_site, scan_result, seed_quarantine,
)

KEV_CVE = CRIT.cve_id  # the CVE seed_quarantine records
OTHER_CVE = "CVE-2026-9999"
TODAY = date(2026, 11, 9)
NOW = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)


def _catalog(*cves: str, age_days: int | None, unreadable: str | None = None) -> KevCatalog:
    fetched = None if age_days is None else NOW - timedelta(days=age_days)
    return KevCatalog(frozenset(cves), fetched, fetched, "https://kev.example/feed.json",
                      unreadable)


def _decisions(*cves: str) -> tuple[ProjectDecision, ...]:
    findings = tuple(FindingDisposition(
        finding=finding(c), base_severity=Severity.CRITICAL, hardening_penalty=0,
        effective_severity=Severity.CRITICAL, disposition=Disposition.STILL_RUNNING_AT_RISK,
        suppression=None, explanation="") for c in cves)
    return (ProjectDecision("demo", "demo-web:1", findings, False, True, NOW),)


def _write_kev(paths, *cves: str, age_days: int) -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    when = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    paths.kev_catalog.write_text(json.dumps({
        "fetched_at": when, "released_at": when, "source": "https://kev.example/feed.json",
        "cve_ids": list(cves)}))


class TestRule:
    def test_a_fresh_catalog_backs_the_lift(self) -> None:
        check = check_kev_for_lift(KEV_CVE, _decisions(KEV_CVE),
                                   _catalog(KEV_CVE, age_days=1), TODAY)
        assert (check.stale, check.refusal, check.gap) == (None, None, None)

    @pytest.mark.parametrize("cve,found,needle", [
        (KEV_CVE, (KEV_CVE,), f"{KEV_CVE} (the quarantine's CVE)"),
        (OTHER_CVE, (KEV_CVE,), f"lists {KEV_CVE}, still in the images"),
    ])
    def test_stale_refuses_when_the_cached_ids_list_a_cve_in_the_images(self, cve, found,
                                                                       needle) -> None:
        check = check_kev_for_lift(cve, _decisions(*found), _catalog(KEV_CVE, age_days=20),
                                   TODAY)
        assert check.refusal is not None and needle in check.refusal
        assert "no KEV catalog has been accepted for 20 days" in check.refusal

    def test_stale_lifts_a_fix_whose_images_no_longer_contain_the_listed_cve(self) -> None:
        check = check_kev_for_lift(KEV_CVE, _decisions("CVE-2026-1111"),
                                   _catalog(KEV_CVE, age_days=20), TODAY)
        assert check.refusal is None and "could not be checked" in check.gap

    def test_stale_without_a_listed_cve_lifts_naming_the_gap(self) -> None:
        check = check_kev_for_lift(OTHER_CVE, _decisions("CVE-2026-1111"),
                                   _catalog(KEV_CVE, age_days=20), TODAY)
        assert check.refusal is None
        assert "added since it was fetched (2026-10-20)" in check.gap

    @pytest.mark.parametrize("kev", [_catalog(age_days=None),
                                     _catalog(age_days=None, unreadable="not JSON")])
    def test_no_usable_catalog_refuses_whatever_the_cve(self, kev) -> None:
        check = check_kev_for_lift(OTHER_CVE, _decisions(), kev, TODAY)
        assert check.refusal is not None and "no usable CISA KEV catalog" in check.refusal


# ---- security resume ----

def _resume_box(tmp_path, monkeypatch, findings, *, cve=KEV_CVE, security=None):
    paths = make_box(tmp_path, security=security or {"posture": "balanced"})
    seed_quarantine(paths, cve_id=cve)
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, findings))
    monkeypatch.setattr(security_resume, "refresh_db", lambda: None)
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                        lambda p, m, component=None: None)
    monkeypatch.setattr(quarantine_lift, "run_smoke", lambda p, paths_: (True, "ok"))
    paths.docker = Docker(monkeypatch)
    paths.pushover = Pushover(monkeypatch, paths)
    paths.logs.mkdir()
    return paths


def test_resume_refuses_the_same_kev_image_on_a_stale_catalog(
        tmp_path, monkeypatch, capsys) -> None:
    paths = _resume_box(tmp_path, monkeypatch, [CRIT])
    _write_kev(paths, KEV_CVE, age_days=20)
    assert cmd_security_resume(["demo"], paths) == 1
    assert is_quarantined("demo", paths)
    err = capsys.readouterr().err
    assert f"{KEV_CVE} (the quarantine's CVE)" in err and "stays in place" in err
    assert "kev.sources" in err and "prod-deploy demo" in err
    assert "--accept-stale-kev does not apply" in err


def test_accept_stale_kev_never_overrides_a_listed_cve_in_the_images(
        tmp_path, monkeypatch, capsys) -> None:
    """A fresh catalog would refuse this lift too; a fix deploy is the exit."""
    paths = _resume_box(tmp_path, monkeypatch, [CRIT])
    _write_kev(paths, KEV_CVE, age_days=20)
    assert cmd_security_resume(["demo", "--accept-stale-kev"], paths) == 1
    assert is_quarantined("demo", paths)
    assert "--accept-stale-kev does not apply" in capsys.readouterr().err
    assert not [t for t, _, _ in paths.pushover.sent if "accept" in t]


def test_resume_lifts_on_a_stale_catalog_listing_nothing_involved_and_alerts(
        tmp_path, monkeypatch, capsys) -> None:
    paths = _resume_box(tmp_path, monkeypatch, [], cve=OTHER_CVE)
    _write_kev(paths, KEV_CVE, age_days=20)
    assert cmd_security_resume(["demo"], paths) == 0
    assert not is_quarantined("demo", paths)
    assert "could not be checked" in capsys.readouterr().out
    alerts = [(t, p) for t, _, p in paths.pushover.sent if "stale KEV catalog" in t]
    assert alerts and alerts[0][1] == 1


@pytest.mark.parametrize("security", [{"posture": "balanced"}, {"posture": "strict"}])
def test_resume_refuses_with_no_catalog_under_every_posture(
        tmp_path, monkeypatch, capsys, security) -> None:
    paths = _resume_box(tmp_path, monkeypatch, [], cve=OTHER_CVE, security=security)
    assert cmd_security_resume(["demo"], paths) == 1
    assert is_quarantined("demo", paths)
    err = capsys.readouterr().err
    assert "no usable CISA KEV catalog" in err and "--accept-stale-kev" in err
    assert "back online" in err and "rests on" not in err


@pytest.mark.parametrize("age,needle", [(0, "the KEV catalog is fresh"),
                                        (20, "stale but lists no CVE in the images")])
def test_accept_stale_kev_with_nothing_to_accept_says_why(
        tmp_path, monkeypatch, capsys, age, needle) -> None:
    paths = _resume_box(tmp_path, monkeypatch, [], cve=OTHER_CVE)
    _write_kev(paths, KEV_CVE, age_days=age)
    assert cmd_security_resume(["demo", "--accept-stale-kev"], paths) == 0
    out = capsys.readouterr().out
    assert "nothing to accept" in out and needle in out
    assert "backs this lift" not in out
    log = paths.log_file.read_text() if paths.log_file.exists() else ""
    assert "accepted with no usable" not in log


def test_accept_stale_kev_lifts_logs_and_alerts(tmp_path, monkeypatch, capsys) -> None:
    paths = _resume_box(tmp_path, monkeypatch, [])
    assert cmd_security_resume(["demo", "--accept-stale-kev"], paths) == 0
    assert not is_quarantined("demo", paths)
    assert "may come back online" in capsys.readouterr().out
    log = paths.log_file.read_text()
    assert "--accept-stale-kev" in log
    alerts = [(t, p) for t, _, p in paths.pushover.sent if "--accept-stale-kev" in t]
    assert alerts and alerts[0][1] == 1


def test_accept_stale_kev_still_refuses_a_quarantine_level_finding(
        tmp_path, monkeypatch, capsys) -> None:
    paths = _resume_box(tmp_path, monkeypatch, [CRIT], security={"posture": "strict"})
    assert cmd_security_resume(["demo", "--accept-stale-kev"], paths) == 1
    assert is_quarantined("demo", paths)
    assert "would still quarantine" in capsys.readouterr().err


def test_resume_lifts_once_the_catalog_is_fresh(tmp_path, monkeypatch) -> None:
    paths = _resume_box(tmp_path, monkeypatch, [])
    _write_kev(paths, OTHER_CVE, age_days=0)
    assert cmd_security_resume(["demo"], paths) == 0
    assert not is_quarantined("demo", paths)
    assert not [t for t, _, _ in paths.pushover.sent if "KEV" in t]


# ---- the deploy gate ----

def _manifest(security=None):
    m = {"project": "demo", "hosts": ["demo.example.com"], "services": {}}
    if security is not None:
        m["security"] = security
    return m


@pytest.fixture
def gate_box(tmp_path, monkeypatch):
    return make_gate_box(tmp_path, monkeypatch)


def make_gate_box(tmp_path, monkeypatch):
    """A quarantined box whose deploy gate scans `paths.scan_findings`."""
    paths = make_box(tmp_path)
    seed_quarantine(paths)
    web = "sha256:" + "a" * 64
    images = {candidate_name("demo", "web"): LocalImage(web, ()),
              "boxmunge.invalid/demo/web": LocalImage(web, ())}
    monkeypatch.setattr(gate, "resolved_services", lambda target: ({}, {
        "web": {"image": candidate_name("demo", "web")}}))
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
    assert "still in the images" in text and "nothing was started" in text
    assert "Ship a release without those CVEs" in text and "kev.sources" in text
    assert "--accept-stale-kev" not in text
    assert "Scan: clear" not in capsys.readouterr().out


def test_gate_lifts_a_fix_on_a_stale_catalog_listing_the_quarantine_cve(gate_box) -> None:
    """The quarantine's CVE is on the cached list, but the fix's images no longer
    contain it: cleared, with the gap carried into the lift alert."""
    _write_kev(gate_box, KEV_CVE, age_days=20)
    clearance = gate.clear_release(gate_box, production_target(gate_box, "demo"), _manifest())
    assert clearance.kev_gap is not None


def test_gate_refuses_with_no_catalog_under_strict_too_naming_the_exits(gate_box) -> None:
    seed_quarantine(gate_box, cve_id=OTHER_CVE)
    with pytest.raises(gate.QuarantineRefused, match="no usable CISA KEV catalog") as e:
        gate.clear_release(gate_box, production_target(gate_box, "demo"),
                           _manifest({"posture": "strict"}))
    text = str(e.value)
    assert "https copy of the feed you host" in text
    assert "security resume demo --accept-stale-kev" in text
    assert "ran when it was quarantined back online" in text
    assert "security suppress <CVE> --project demo" in text
    assert "security unsuppress <CVE> --project demo" in text


def test_gate_clears_on_a_stale_catalog_listing_nothing_and_carries_the_gap(gate_box) -> None:
    seed_quarantine(gate_box, cve_id=OTHER_CVE)
    _write_kev(gate_box, KEV_CVE, age_days=20)
    clearance = gate.clear_release(gate_box, production_target(gate_box, "demo"), _manifest())
    assert clearance.kev_gap is not None and "could not be checked" in clearance.kev_gap
    message, detail = gate._lift_report(clearance, "v2")
    assert "could not be checked" in message and detail["kev_gap"] == clearance.kev_gap


def test_gate_clears_once_the_catalog_is_fresh(gate_box) -> None:
    _write_kev(gate_box, KEV_CVE, age_days=0)
    clearance = gate.clear_release(gate_box, production_target(gate_box, "demo"), _manifest())
    assert clearance.kev_gap is None


def test_staging_is_not_judged_against_the_catalog(gate_box) -> None:
    """Staging lifts nothing; the promote is judged again."""
    staged = dataclasses.replace(production_target(gate_box, "demo"), staging=True)
    clearance = gate.clear_release(gate_box, staged, _manifest())
    assert clearance.kev_gap is None
