# SPDX-License-Identifier: Apache-2.0
"""Table-driven check: evaluate_finding against CVE_POLICY.md's decision order.

Every row is one finding shape; every cell is the disposition CVE_POLICY.md
promises for that shape under one posture. The table encodes the DOCUMENT,
not the implementation's literal output: when the two disagree the cell is
marked xfail(strict=True) with the audit finding ID, and the mark comes off
in the commit that brings code and doc back into agreement.

Origin: the v0.11 audit (area B) 88-cell decision-order check, made permanent.
"""
from __future__ import annotations

from datetime import date

import pytest

from boxmunge.cve.policy import Disposition, Posture, evaluate_finding
from boxmunge.cve.scanner import AttackVector as AV
from boxmunge.cve.scanner import Finding, PkgClass, Severity
from boxmunge.cve.scanner import VulnStatus as VS
from boxmunge.cve.suppressions import Suppression

_TODAY = date(2026, 10, 13)
_SUP = (Suppression("CVE-2026-0001", date(2027, 1, 1), "reviewed", "ops", date(2026, 1, 1)),)

R, B, S, P = Posture.RELAXED, Posture.BALANCED, Posture.STRICT, Posture.PARANOID
I = Disposition.INFORMATIONAL  # noqa: E741 — table legibility
Q = Disposition.QUARANTINE
X = Disposition.IGNORED_FIXED
SU = Disposition.SUPPRESSED
SR = Disposition.STILL_RUNNING_AT_RISK


def _f(
    *, sev: Severity = Severity.HIGH, fix: str | None = None,
    av: AV | None = AV.NETWORK, status: VS = VS.AFFECTED,
    vendor: dict[str, Severity] | None = None, pkg: str = "openssl",
) -> Finding:
    return Finding(
        cve_id="CVE-2026-0001", severity=sev, package=pkg, installed_version="1",
        fixed_version=fix, title="", primary_url=None, attack_vector=av,
        status=status,
        vendor_severities=vendor if vendor is not None else {"debian": sev},
        pkg_class=PkgClass.OS,
    )


# (row id, finding, evaluate kwargs, {posture: documented disposition})
_ROWS: list[tuple[str, Finding, dict, dict[Posture, Disposition]]] = [
    ("fix-available+kev", _f(fix="2"), {"kev": True}, {R: X, B: X, S: X, P: X}),
    ("suppressed", _f(), {"sup": _SUP}, {R: SU, B: SU, S: SU, P: SU}),
    ("suppressed+kev", _f(), {"kev": True, "sup": _SUP}, {R: Q, B: Q, S: Q, P: Q}),
    ("kev-low-avl-will-not-fix",
     _f(sev=Severity.LOW, av=AV.LOCAL, status=VS.WILL_NOT_FIX), {"kev": True},
     {R: Q, B: Q, S: Q, P: Q}),
    ("kev+ddq", _f(), {"kev": True, "ddq": True}, {R: SR, B: SR, S: SR, P: SR}),
    ("unknown-severity", _f(sev=Severity.UNKNOWN, vendor={}), {}, {R: I, B: I, S: I, P: I}),
    ("high-avn-affected", _f(), {}, {R: I, B: Q, S: Q, P: Q}),
    ("medium-avn-affected", _f(sev=Severity.MEDIUM), {}, {R: I, B: I, S: Q, P: Q}),
    ("low-avn-affected", _f(sev=Severity.LOW), {}, {R: I, B: I, S: I, P: I}),
    ("high-avl-affected", _f(av=AV.LOCAL), {}, {R: I, B: I, S: I, P: Q}),
    ("high-av-unknown", _f(av=None), {}, {R: I, B: I, S: I, P: Q}),
    ("critical-will-not-fix", _f(sev=Severity.CRITICAL, status=VS.WILL_NOT_FIX), {},
     {R: I, B: I, S: I, P: Q}),
    ("high-under-investigation", _f(status=VS.UNDER_INVESTIGATION), {},
     {R: I, B: I, S: I, P: Q}),
    ("high-end-of-life", _f(status=VS.END_OF_LIFE), {}, {R: I, B: Q, S: Q, P: Q}),
    # A missing/unknown distro Status is not a distro de-prioritisation, so
    # it falls through to the threshold (fail-closed). CVE_POLICY.md step 11.
    ("high-status-unknown", _f(status=VS.UNKNOWN), {}, {R: I, B: Q, S: Q, P: Q}),
    ("nvd-high-no-distro-verdict", _f(vendor={"nvd": Severity.HIGH}), {},
     {R: I, B: I, S: I, P: Q}),
    ("nvd-critical-debian-low",
     _f(sev=Severity.CRITICAL, vendor={"debian": Severity.LOW, "nvd": Severity.CRITICAL}),
     {}, {R: I, B: I, S: I, P: Q}),
    # Trivy resolves Severity distro-first; paranoid is documented as NVD.
    ("trivy-low-nvd-critical",
     _f(sev=Severity.LOW, vendor={"debian": Severity.LOW, "nvd": Severity.CRITICAL}),
     {}, {R: I, B: I, S: I, P: Q}),
    ("medium-penalty-1", _f(sev=Severity.MEDIUM), {"pen": 1}, {R: I, B: Q, S: Q, P: Q}),
    ("perl-base-python-project", _f(pkg="perl-base"), {}, {R: I, B: I, S: I, P: Q}),
    ("perl-base-kev", _f(pkg="perl-base"), {"kev": True}, {R: Q, B: Q, S: Q, P: Q}),
    ("python3-empty-inferred-runtimes", _f(pkg="python3.11"),
     {"runtimes": frozenset()}, {R: I, B: I, S: I, P: Q}),
    ("libperl-stays-relevant", _f(pkg="libperl5.36"), {}, {R: I, B: Q, S: Q, P: Q}),
    ("high-ddq", _f(), {"ddq": True}, {R: I, B: SR, S: SR, P: SR}),
]

# Cells where the code currently disagrees with CVE_POLICY.md, keyed by
# (row id, posture) → audit finding ID. Remove an entry in the commit that
# fixes it; strict xfail turns an unexpected pass into a failure.
_KNOWN_WRONG: dict[tuple[str, Posture], str] = {
    **{("kev+ddq", p): "B-09: KEV ignores dangerously_disable_quarantine" for p in Posture},
    ("trivy-low-nvd-critical", P): "B-08: paranoid compares Trivy's resolved severity, not NVD",
}


def _evaluate(finding: Finding, posture: Posture, *, kev: bool = False,
              ddq: bool = False, sup: tuple = (), pen: int = 0,
              runtimes: frozenset[str] = frozenset({"python"})) -> Disposition:
    return evaluate_finding(
        finding, posture=posture, hardening_penalty=pen,
        dangerously_disable_quarantine=ddq, suppressions=sup, today=_TODAY,
        kev_lookup=lambda _cve: kev, runtimes=runtimes,
    ).disposition


def _cells():
    for row_id, finding, kwargs, expected in _ROWS:
        for posture, want in expected.items():
            marks = []
            reason = _KNOWN_WRONG.get((row_id, posture))
            if reason:
                marks.append(pytest.mark.xfail(strict=True, reason=reason))
            yield pytest.param(
                finding, posture, kwargs, want,
                id=f"{row_id}-{posture.value}", marks=marks,
            )


def test_table_covers_every_posture_for_every_row() -> None:
    assert all(set(expected) == set(Posture) for _, _, _, expected in _ROWS)


@pytest.mark.parametrize(("finding", "posture", "kwargs", "want"), list(_cells()))
def test_decision_order_matches_cve_policy(finding, posture, kwargs, want) -> None:
    assert _evaluate(finding, posture, **kwargs) is want
