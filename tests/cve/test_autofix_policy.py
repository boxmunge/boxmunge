# SPDX-License-Identifier: Apache-2.0
"""Autofix decisions: how soon a finding is patched, and whether the site goes
dark while it is (the CVE autofix flowcharts, table A and chart 2).

The dispositions come from the real policy engine, so these tests also pin
what the engine records for autofix to read.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timezone

import pytest

from boxmunge.cve.autofix_policy import (
    CVSS_DOWNTIME_THRESHOLD,
    AutofixUrgency,
    downtime_while_patching,
    nightly_eligible,
    urgency,
)
from boxmunge.cve.exploited import ExploitedSource
from boxmunge.cve.policy import (
    Disposition, FindingDisposition, Posture, ProjectDecision, evaluate_finding,
)
from boxmunge.cve.scan_state import decisions_from_scan_state, read_scan_state, write_scan_state
from boxmunge.cve.scanner import AttackVector, Finding, PkgClass, Severity, VulnStatus
from boxmunge.cve.suppressions import Suppression

_TODAY = date(2026, 11, 14)
R, B, S, P = Posture.RELAXED, Posture.BALANCED, Posture.STRICT, Posture.PARANOID
_CISA = frozenset({ExploitedSource.CISA})
_EU = frozenset({ExploitedSource.EU})
_VC = frozenset({ExploitedSource.VULNCHECK})
_SUP = (Suppression("CVE-2026-0001", date(2027, 1, 1), "reviewed", "ops", date(2026, 1, 1)),)


def _f(*, sev: Severity = Severity.HIGH, fix: str | None = "2", cvss: float | None = 7.5,
       pkg_class: PkgClass = PkgClass.OS, av: AttackVector = AttackVector.NETWORK) -> Finding:
    return Finding(
        cve_id="CVE-2026-0001", severity=sev, package="openssl", installed_version="1",
        fixed_version=fix, title="", primary_url=None, attack_vector=av,
        status=VulnStatus.AFFECTED, vendor_severities={"debian": sev},
        pkg_class=pkg_class, cvss_score=cvss,
    )


def _judge(finding: Finding, posture: Posture, *, listed: frozenset = frozenset(),
           sup: tuple = (), ddq: bool = False, pen: int = 0) -> FindingDisposition:
    return evaluate_finding(
        finding, posture=posture, hardening_penalty=pen,
        dangerously_disable_quarantine=ddq, suppressions=sup, today=_TODAY,
        exploited_lookup=lambda _cve: listed, runtimes=frozenset({"python"}),
    )


# ---------- table A: downtime while patching ----------

_TABLE_A = {  # posture → (full KEV CVSS < 9, full KEV CVSS >= 9, VulnCheck only)
    R: (False, False, False),
    B: (False, True, False),
    S: (True, True, False),
    P: (True, True, True),
}


def _table_a_cells():
    for posture, (low, high, vulncheck) in _TABLE_A.items():
        yield pytest.param(posture, _CISA, 7.5, low, id=f"{posture.value}-kev-below-9")
        yield pytest.param(posture, _EU, 9.8, high, id=f"{posture.value}-kev-9-or-more")
        yield pytest.param(posture, _VC, 9.8, vulncheck, id=f"{posture.value}-vulncheck-only")


@pytest.mark.parametrize(("posture", "listed", "cvss", "dark"), list(_table_a_cells()))
def test_downtime_while_patching_matches_table_a(posture, listed, cvss, dark) -> None:
    fd = _judge(_f(cvss=cvss), posture, listed=listed)
    assert downtime_while_patching(fd, posture) is dark


@pytest.mark.parametrize(("posture", "dark"), [(p, cells[1]) for p, cells in _TABLE_A.items()])
def test_unrated_cvss_counts_as_9_or_more(posture, dark) -> None:
    fd = _judge(_f(cvss=None), posture, listed=_CISA)
    assert downtime_while_patching(fd, posture) is dark


def test_the_cvss_threshold_is_inclusive() -> None:
    assert CVSS_DOWNTIME_THRESHOLD == 9.0
    assert downtime_while_patching(_judge(_f(cvss=9.0), B, listed=_CISA), B)
    assert not downtime_while_patching(_judge(_f(cvss=8.9), B, listed=_CISA), B)


def test_a_finding_off_the_patch_path_has_no_table_a_answer() -> None:
    for finding in (_f(fix=None), _f(pkg_class=PkgClass.LANG)):
        with pytest.raises(ValueError, match="patch path"):
            downtime_while_patching(_judge(finding, B, listed=_CISA), B)


def test_paranoid_takes_the_downtime_for_a_fixable_finding_at_its_gate() -> None:
    fd = _judge(_f(sev=Severity.MEDIUM), P)
    assert downtime_while_patching(fd, P)
    for posture in (R, B, S):
        assert not downtime_while_patching(_judge(_f(), posture), posture)


# ---------- the 0.12 posture rules ----------


def test_strict_no_fix_awaits_instead_of_quarantine() -> None:
    for sev in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        fd = _judge(_f(sev=sev, fix=None), S)
        assert fd.disposition is Disposition.AWAITING_FIX
        assert "strict posture" in fd.explanation and "stays up" in fd.explanation
    # Opting out of quarantine changes nothing: there is no quarantine to opt out of.
    assert _judge(_f(fix=None), S, ddq=True).disposition is Disposition.AWAITING_FIX
    assert _judge(_f(sev=Severity.LOW, fix=None), S).disposition is Disposition.INFORMATIONAL


def test_paranoid_fixable_at_gate_quarantines() -> None:
    fd = _judge(_f(sev=Severity.MEDIUM), P)
    assert fd.disposition is Disposition.QUARANTINE
    assert "2" in fd.explanation and "paranoid" in fd.explanation
    assert "quarantined until" in fd.explanation
    assert _judge(_f(sev=Severity.MEDIUM), P, ddq=True).disposition is (
        Disposition.STILL_RUNNING_AT_RISK)
    # Below the gate, or suppressed, a fix is still just a fix not running.
    assert _judge(_f(sev=Severity.LOW), P).disposition is Disposition.IGNORED_FIXED
    assert _judge(_f(), P, sup=_SUP).disposition is Disposition.IGNORED_FIXED
    assert urgency(fd, P) is AutofixUrgency.URGENT


# ---------- urgency and the nightly window ----------


@pytest.mark.parametrize("posture", list(Posture))
@pytest.mark.parametrize("listed", [_CISA, _EU, _VC], ids=["cisa", "eu", "vulncheck"])
def test_a_fixable_known_exploited_os_finding_is_urgent(posture, listed) -> None:
    for fd in (_judge(_f(), posture, listed=listed),
               _judge(_f(), posture, listed=listed, sup=_SUP),
               _judge(_f(), posture, listed=listed, ddq=True)):
        assert urgency(fd, posture) is AutofixUrgency.URGENT


@pytest.mark.parametrize("posture", [B, S])
def test_a_fixable_finding_at_the_gate_waits_for_the_nightly_window(posture) -> None:
    fd = _judge(_f(), posture)
    assert fd.disposition is Disposition.IGNORED_FIXED and fd.fix_would_quarantine
    assert nightly_eligible(fd, posture)
    assert urgency(fd, posture) is AutofixUrgency.NIGHTLY


def test_strict_gate_is_medium_for_the_nightly_window() -> None:
    """Strict's gate now yields AWAITING_FIX, which still counts as meeting it."""
    fd = _judge(_f(sev=Severity.MEDIUM), S)
    assert fd.fix_would_quarantine and nightly_eligible(fd, S)
    assert not nightly_eligible(_judge(_f(sev=Severity.MEDIUM), B), B)


def test_relaxed_nightly_uses_balanced_gate() -> None:
    high = _judge(_f(), R)
    assert high.disposition is Disposition.IGNORED_FIXED
    assert not high.fix_would_quarantine  # relaxed still alerts nothing for it
    assert nightly_eligible(high, R) and urgency(high, R) is AutofixUrgency.NIGHTLY
    assert not nightly_eligible(_judge(_f(sev=Severity.MEDIUM), R), R)
    assert not nightly_eligible(_judge(_f(av=AttackVector.LOCAL), R), R)


def test_paranoid_never_waits_for_the_nightly_window() -> None:
    fd = _judge(_f(sev=Severity.MEDIUM), P)
    assert not nightly_eligible(fd, P)
    assert urgency(fd, P) is AutofixUrgency.URGENT


@pytest.mark.parametrize("posture", list(Posture))
def test_low_negligible_suppressed_never_eligible(posture) -> None:
    for fd in (_judge(_f(sev=Severity.LOW), posture),
               _judge(_f(sev=Severity.UNKNOWN), posture),
               _judge(_f(sev=Severity.CRITICAL), posture, sup=_SUP)):
        assert not nightly_eligible(fd, posture)
        assert urgency(fd, posture) is AutofixUrgency.NONE


@pytest.mark.parametrize("posture", list(Posture))
def test_lang_package_never_eligible(posture) -> None:
    for listed in (frozenset(), _CISA, _VC):
        fd = _judge(_f(sev=Severity.CRITICAL, pkg_class=PkgClass.LANG), posture, listed=listed)
        assert not nightly_eligible(fd, posture)
        assert urgency(fd, posture) is AutofixUrgency.NONE
    unknown = _judge(_f(sev=Severity.CRITICAL, pkg_class=PkgClass.UNKNOWN), posture)
    assert urgency(unknown, posture) is AutofixUrgency.NONE


@pytest.mark.parametrize("posture", list(Posture))
def test_a_finding_with_no_fix_has_nothing_to_patch(posture) -> None:
    for listed in (frozenset(), _CISA, _VC):
        fd = _judge(_f(sev=Severity.CRITICAL, fix=None), posture, listed=listed)
        assert not nightly_eligible(fd, posture)
        assert urgency(fd, posture) is AutofixUrgency.NONE


def test_eligibility_reads_the_recorded_gate_not_the_disposition() -> None:
    """A disposition read back without the gate flag is not eligible: the flag,
    not a guess from the disposition, decides."""
    fd = _judge(_f(), B)
    assert not nightly_eligible(replace(fd, fix_meets_patch_gate=False), B)


def test_the_patch_gate_survives_the_scan_state(tmp_path) -> None:
    """The nightly run may read decisions back: the flag must not drop to False."""
    path = tmp_path / "scan.json"
    for fd in (_judge(_f(), R), _judge(_f(sev=Severity.LOW), R)):
        write_scan_state(path, decisions=(ProjectDecision(
            project_name="shop", image_ref="shop-web:1", findings=(fd,),
            quarantine_required=False, at_risk_running=False,
            scanned_at=datetime(2026, 11, 14, tzinfo=timezone.utc)),))
        [back] = decisions_from_scan_state(read_scan_state(path), project_name="shop")
        assert back.findings[0].fix_meets_patch_gate is fd.fix_meets_patch_gate
        assert nightly_eligible(back.findings[0], R) is nightly_eligible(fd, R)
