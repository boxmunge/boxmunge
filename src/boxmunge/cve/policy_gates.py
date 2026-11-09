# SPDX-License-Identifier: Apache-2.0
"""Disposition builders of the CVE policy engine: severity choice and gates.

Split from policy.py (the trust ladder) to keep it under the file-size
budget. Pure functions; consumers import from ``boxmunge.cve.policy``.
"""
from __future__ import annotations

from boxmunge.cve.policy_explain import explain_awaiting_fix, explain_threshold
from boxmunge.cve.policy_types import (
    _POSTURE_LABEL,
    _SEVERITY_GATES,
    _SEVERITY_RANK,
    Disposition,
    FindingDisposition,
    Posture,
)
from boxmunge.cve.scanner import Finding, Severity


def paranoid_severity(finding: Finding) -> tuple[Severity, tuple[str, ...]]:
    """The highest severity any source reports, and the sources reporting it.

    Trivy's own resolved severity counts too (as "trivy"), but is named only
    when no vendor source gives the same rating.
    """
    ratings = finding.vendor_severities
    highest = max((finding.severity, *ratings.values()), key=_SEVERITY_RANK.__getitem__)
    sources = sorted((src for src, sev in ratings.items() if sev is highest),
                     key=lambda src: (src != "nvd", src))
    return highest, tuple(sources) or ("trivy",)


def informational(
    finding: Finding,
    base: Severity,
    penalty: int,
    effective: Severity,
    explanation: str,
) -> FindingDisposition:
    """Construct an INFORMATIONAL disposition (DRYs the repeated boilerplate)."""
    return FindingDisposition(
        finding=finding,
        base_severity=base,
        hardening_penalty=penalty,
        effective_severity=effective,
        disposition=Disposition.INFORMATIONAL,
        suppression=None,
        explanation=explanation,
    )


def threshold_disposition(
    finding: Finding,
    base: Severity,
    effective: Severity,
    penalty: int,
    posture: Posture,
    *,
    compare_sev: Severity,
    dangerously_disable_quarantine: bool,
    severity_sources: tuple[str, ...] = (),
) -> FindingDisposition:
    """Compare `compare_sev` against the posture's severity gate and dispose.

    `effective` is what the operator sees on the disposition (the severity the
    decision was made on): highest-rating-effective under paranoid, named by
    `severity_sources`, distro-effective below it. `compare_sev` is the value
    actually compared. A gate that quarantines yields STILL_RUNNING_AT_RISK
    when the project opted out; balanced's alert-only gate yields
    AWAITING_FIX either way (there is no quarantine to opt out of).
    """
    threshold, action = _SEVERITY_GATES[posture]
    over = _SEVERITY_RANK[compare_sev] >= _SEVERITY_RANK[threshold]
    label = _POSTURE_LABEL[posture]
    if over and action is Disposition.AWAITING_FIX:
        disposition = action
        explanation = explain_awaiting_fix(base, effective, penalty, label, threshold.value)
    else:
        if not over:
            disposition = Disposition.INFORMATIONAL
        elif dangerously_disable_quarantine:
            disposition = Disposition.STILL_RUNNING_AT_RISK
        else:
            disposition = Disposition.QUARANTINE
        explanation = explain_threshold(
            base, effective, penalty, label, threshold.value,
            over_threshold=over,
            dangerously_disabled=dangerously_disable_quarantine,
            severity_sources=severity_sources,
        )
    return FindingDisposition(
        finding=finding,
        base_severity=base,
        hardening_penalty=penalty,
        effective_severity=effective,
        disposition=disposition,
        suppression=None,
        explanation=explanation,
    )
