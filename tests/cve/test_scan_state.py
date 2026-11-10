# SPDX-License-Identifier: Apache-2.0
"""Tests for scan_state persistence of the VulnStatus `status` field."""

from datetime import datetime, timezone

import pytest

from boxmunge.cve.policy import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.scanner import AttackVector, Finding, PkgClass, Severity, VulnStatus


# ---------- helpers ----------


def _finding(
    cve_id: str = "CVE-2026-9999",
    severity: Severity = Severity.HIGH,
    status: VulnStatus = VulnStatus.UNKNOWN,
    pkg_class: PkgClass = PkgClass.UNKNOWN,
    pkg_type: str | None = None,
) -> Finding:
    return Finding(
        cve_id=cve_id,
        severity=severity,
        package="libssl",
        installed_version="1.1.1k",
        fixed_version=None,
        title="Test CVE",
        primary_url=None,
        attack_vector=AttackVector.NETWORK,
        status=status,
        pkg_class=pkg_class,
        pkg_type=pkg_type,
    )


def _make_decision(
    status: VulnStatus = VulnStatus.UNKNOWN,
    pkg_class: PkgClass = PkgClass.UNKNOWN,
    pkg_type: str | None = None,
) -> ProjectDecision:
    fd = FindingDisposition(
        finding=_finding(status=status, pkg_class=pkg_class, pkg_type=pkg_type),
        base_severity=Severity.HIGH,
        hardening_penalty=0,
        effective_severity=Severity.HIGH,
        disposition=Disposition.INFORMATIONAL,
        suppression=None,
        explanation="test",
    )
    return ProjectDecision(
        project_name="p",
        image_ref="img@sha256:abc",
        findings=(fd,),
        quarantine_required=False,
        at_risk_running=False,
        scanned_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )


# ---------- tests ----------


def test_scan_state_roundtrips_status(tmp_path):
    """Writing and reading back a decision preserves the status field."""
    from boxmunge.cve.scan_state import (
        decisions_from_scan_state,
        read_scan_state,
        write_scan_state,
    )

    decision = _make_decision(status=VulnStatus.WILL_NOT_FIX)
    path = tmp_path / "state.json"
    write_scan_state(path, decisions=(decision,))
    state = read_scan_state(path)
    assert state is not None
    restored = decisions_from_scan_state(state, project_name="p")
    assert restored[0].findings[0].finding.status is VulnStatus.WILL_NOT_FIX


def _stored(**overrides):
    finding = {
        "cve_id": "CVE-9", "base_severity": "High",
        "effective_severity": "High", "hardening_penalty": 0,
        "disposition": "informational", "explanation": "x",
        "fix_available": False, "fixed_version": None,
        "package": "p", "primary_url": None, "title": "t",
        "installed_version": "1", "attack_vector": None,
        "status": "affected", "pkg_class": "os-pkgs", "pkg_type": "debian",
    }
    finding.update(overrides)
    for key in [k for k, v in overrides.items() if v is _MISSING]:
        del finding[key]
    return {"scanned_at": "2026-06-01T00:00:00+00:00",
            "decisions": [{"image_ref": "img@sha256:abc", "findings": [finding]}]}


_MISSING = object()


def test_a_stored_finding_with_no_attack_vector_reads_back_as_none():
    from boxmunge.cve.scan_state import decisions_from_scan_state
    [decision] = decisions_from_scan_state(_stored(), project_name="p")
    assert decision.findings[0].finding.attack_vector is None


@pytest.mark.parametrize("field, value", [
    ("base_severity", "Severe"), ("effective_severity", _MISSING),
    ("status", _MISSING), ("status", "maybe"),
    ("pkg_class", _MISSING), ("pkg_class", "os"),
    ("attack_vector", "SATELLITE"), ("disposition", "quarantined-ish"),
])
def test_an_unrecognised_stored_value_is_refused_naming_its_field(field, value):
    """A corrupted or hand-edited field is an unreadable file, not "unknown":
    reading it as unknown would silently skew the transition alerts."""
    from boxmunge.cve.scan_state import decisions_from_scan_state
    from boxmunge.state import StateError
    with pytest.raises(StateError, match=field):
        decisions_from_scan_state(_stored(**{field: value}), project_name="p")


def test_scan_state_roundtrips_pkg_class(tmp_path):
    """Writing and reading back a decision preserves pkg_class and pkg_type."""
    from boxmunge.cve.scan_state import (
        decisions_from_scan_state,
        read_scan_state,
        write_scan_state,
    )

    decision = _make_decision(pkg_class=PkgClass.OS, pkg_type="debian")
    path = tmp_path / "state.json"
    write_scan_state(path, decisions=(decision,))
    state = read_scan_state(path)
    assert state is not None
    restored = decisions_from_scan_state(state, project_name="p")
    assert restored[0].findings[0].finding.pkg_class is PkgClass.OS
    assert restored[0].findings[0].finding.pkg_type == "debian"


@pytest.mark.parametrize("content", ["{not json", "[]"])
def test_unreadable_scan_state_names_the_file(tmp_path, content):
    from boxmunge.cve.scan_state import read_scan_state
    from boxmunge.state import StateError

    path = tmp_path / "state.json"
    path.write_text(content)
    with pytest.raises(StateError, match=str(path)):
        read_scan_state(path)
