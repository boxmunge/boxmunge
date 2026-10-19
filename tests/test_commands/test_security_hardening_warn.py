# SPDX-License-Identifier: Apache-2.0
"""0.11.0 warns about what the stricter hardening penalty will quarantine.

The penalty now counts a compose-only service without `read_only: true` (and
a manifest `cap_add` / `no_new_privileges: false`). Until
STRICT_HARDENING_PENALTY_ENFORCED a finding that only that penalty lifts over
the posture threshold is flagged and alerted once, never quarantined and
never a reason to refuse a deploy. A finding the 0.10.1 penalty already lifts
behaves as ever. The real scan, policy, alerting and gate code run; only
Docker and Trivy are stubbed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import yaml

from boxmunge.commands import quarantine_gate as gate
from boxmunge.commands import security_scan_core
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.commands.security_views import _format_findings_block
from boxmunge.cve import hardening
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scanner import Severity
from boxmunge.health_checks.security import check_cve_hardening_upcoming
from boxmunge.release_target import production_target
from tests.test_commands.cve_helpers import Docker, Pushover, finding, make_box, scan_result
from tests.test_commands.test_quarantine_gate import MANIFEST, Box

MEDIUM = finding("CVE-2026-5555", sev=Severity.MEDIUM)
UPCOMING_TITLE = "will quarantine from 0.12"


def _kev() -> KevCatalog:
    return KevCatalog(frozenset(), datetime.now(timezone.utc))


def _scan_box(tmp_path, monkeypatch, db: dict, posture: str = "balanced"):
    """The manifest declares web; the compose-only db is ``db``."""
    paths = make_box(tmp_path, security={"posture": posture})
    (paths.projects / "demo" / "compose.yml").write_text(yaml.safe_dump({"services": {
        "web": {"image": "demo-web:1"}, "db": {"image": "postgres:16", **db}}}))
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, [MEDIUM]))
    Docker(monkeypatch)
    return paths, Pushover(monkeypatch, paths)


def _scan(paths):
    return scan_one_project(paths, "demo", in_grace=False, kev=_kev())


def test_a_compose_only_writable_db_warns_and_does_not_quarantine(tmp_path, monkeypatch) -> None:
    paths, pushover = _scan_box(tmp_path, monkeypatch, {})
    scan = _scan(paths)
    fd = scan.decisions[0].findings[0]
    assert fd.disposition is Disposition.INFORMATIONAL and fd.hardening_penalty == 0
    assert fd.hardening_would_quarantine
    assert "From 0.12" in fd.explanation and "db" in fd.explanation
    assert "`read_only: true`" in fd.explanation
    assert not is_quarantined("demo", paths)
    [(title, body, priority)] = pushover.sent
    assert UPCOMING_TITLE in title and priority == 0
    assert "CVE-2026-5555" in body and "db" in body and "read_only: true" in body
    # Warned once per finding: the next scan is silent, the warning stands.
    pushover.clear()
    assert _scan(paths).decisions[0].findings[0].hardening_would_quarantine
    assert pushover.sent == []


def test_the_warning_shows_in_status_health_and_survives_the_scan_state(
        tmp_path, monkeypatch) -> None:
    paths, _ = _scan_box(tmp_path, monkeypatch, {})
    _scan(paths)
    state = json.loads(paths.project_scan_state("demo").read_text())
    assert state["decisions"][0]["findings"][0]["hardening_would_quarantine"] is True
    text = "\n".join(_format_findings_block(state))
    assert "WARN: 2 finding(s) will quarantine this project from 0.12" in text
    assert "[WARN" in text and "INFORMATIONAL" not in text
    assert "WARNING, not quarantined yet: the stricter hardening penalty would quarantine" in text
    check = check_cve_hardening_upcoming(paths)
    assert check.status == "warn" and "demo: 1 finding(s)" in check.detail
    assert "read_only: true" in check.detail


def test_a_finding_the_legacy_penalty_already_lifts_quarantines_as_before(
        tmp_path, monkeypatch) -> None:
    paths, pushover = _scan_box(tmp_path, monkeypatch, {"read_only": False})
    fd = _scan(paths).decisions[0].findings[0]
    assert fd.disposition is Disposition.QUARANTINE and fd.hardening_penalty == 1
    assert not fd.hardening_would_quarantine
    assert is_quarantined("demo", paths)
    assert not any(UPCOMING_TITLE in t for t in pushover.titles())


def test_enforced_the_same_finding_quarantines(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(hardening, "STRICT_HARDENING_PENALTY_ENFORCED", True)
    paths, _ = _scan_box(tmp_path, monkeypatch, {})
    fd = _scan(paths).decisions[0].findings[0]
    assert fd.disposition is Disposition.QUARANTINE and fd.hardening_penalty == 1
    assert not fd.hardening_would_quarantine
    assert is_quarantined("demo", paths)


def test_a_hardened_compose_only_db_has_nothing_to_warn_about(tmp_path, monkeypatch) -> None:
    paths, pushover = _scan_box(tmp_path, monkeypatch, {"read_only": True})
    fd = _scan(paths).decisions[0].findings[0]
    assert not fd.hardening_would_quarantine and fd.disposition is Disposition.INFORMATIONAL
    assert check_cve_hardening_upcoming(paths).status == "ok"
    assert not any(UPCOMING_TITLE in t for t in pushover.titles())


def test_the_digest_does_not_repeat_a_warned_finding(tmp_path, monkeypatch) -> None:
    paths, pushover = _scan_box(tmp_path, monkeypatch, {})
    _scan(paths)
    assert not any("new CVE finding" in t for t in pushover.titles())


# ---- the deploy-time gate ----


@pytest.fixture
def box(tmp_path, monkeypatch) -> Box:
    b = Box(tmp_path, monkeypatch)
    b.findings["postgres@sha256:" + "b" * 64] = (MEDIUM,)
    return b


def _compose(box, monkeypatch, **db) -> None:
    services = {n: ({"read_only": True} if n != "db" else db) for n in box.services}
    monkeypatch.setattr(gate, "resolve_deployed_config", lambda *a, **k: {"services": services})


def test_the_gate_warns_and_clears_a_release_only_the_new_penalty_lifts(
        box, monkeypatch, capsys) -> None:
    _compose(box, monkeypatch)
    assert box.clear(MANIFEST).cve_id == "CVE-2026-0001"
    out = capsys.readouterr().out
    assert "WARNING: from 0.12 this release would still be quarantined" in out
    assert "CVE-2026-5555" in out and "service db" in out and "read_only: true" in out


def test_the_gate_refuses_what_the_legacy_penalty_already_lifts(box, monkeypatch) -> None:
    _compose(box, monkeypatch, read_only=False)
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear(MANIFEST)
    assert "CVE-2026-5555" in str(e.value)


def test_the_gate_refuses_once_the_strict_penalty_is_enforced(box, monkeypatch) -> None:
    monkeypatch.setattr(hardening, "STRICT_HARDENING_PENALTY_ENFORCED", True)
    _compose(box, monkeypatch)
    with pytest.raises(gate.QuarantineRefused) as e:
        box.clear(MANIFEST)
    assert "CVE-2026-5555" in str(e.value)


def test_require_unchanged_ignores_a_change_only_the_new_penalty_sees(
        box, monkeypatch) -> None:
    _compose(box, monkeypatch, read_only=True)
    clearance = box.clear(MANIFEST)
    _compose(box, monkeypatch)  # a hook dropped the db's read_only
    monkeypatch.setattr(gate, "production_target", lambda *a: production_target(box.paths, "demo"))
    gate.require_unchanged(box.paths, clearance)


def test_the_undeclared_service_warning_names_the_penalty_and_0_12() -> None:
    from boxmunge.security_warn import undeclared_service_warning
    text = undeclared_service_warning("demo", "db")
    assert "+1 to the CVE severity of every finding in the whole project" in text
    assert "only warns" in text and "from 0.12 it quarantines" in text
