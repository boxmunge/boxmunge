# SPDX-License-Identifier: Apache-2.0
"""CVE policy decision engine — pure-function gate over scan findings.

Inputs: scan findings, project posture, hardening profile, suppressions.
Output: a structured decision per finding, aggregated to a project decision.

This module is deliberately I/O-free: callers (cron job, deploy gate, CLI)
are responsible for the actions implied by a decision (quarantine, alert,
audit-log append). The split keeps the decision logic deterministic and
unit-testable, and lets the same engine drive scheduled scans and
ad-hoc CLI inspection from one source of truth.

The trust ladder (non-paranoid postures trust the distro's own triage):
    relaxed  → quarantine only on CISA KEV (actively exploited).
    balanced → KEV OR distro status:affected + distro severity ≥ High + AV:N.
    strict   → KEV OR distro status:affected + distro severity ≥ Medium + AV:N.
    paranoid → anything ≥ Medium over threshold; no distro trust, no AV
               filter, NVD severity (the pre-trust-ladder behavior). KEV can
               still escalate.

KEV is an override applied right after the fix check and BEFORE
suppressions: an actively exploited CVE quarantines regardless of posture,
distro status, attack vector, threshold, or an operator suppression (a
suppression reviewed before the CVE was known to be exploited must not
keep hiding it — audit B-07).

Below paranoid, a finding is otherwise routed to INFORMATIONAL when the
distro deprioritized it (status will_not_fix / fix_deferred / not_affected /
under_investigation), when there is no distro verdict at all (only NVD/GHSA
rated it), or when it fails the v0.7.1 Attack Vector filter. Only the
remaining distro-acknowledged, network-reachable findings reach the severity
threshold — compared against the *distro* severity, elevated by the
hardening penalty.

A finding is also routed to INFORMATIONAL — below paranoid — when its
package belongs to a language runtime the project does not use (a Perl bug
cannot run in a Python-only image). This gate consults only
positively-identified runtime families, so ordinary system libraries such
as openssl remain quarantinable.

Effective severity = the severity the decision was made on, elevated by a
hardening penalty (capped at Critical). The penalty captures deviations from
the boxmunge overlay's hardened defaults — running with read_only disabled
means a Medium CVE behaves more like a High one in practice.
"""

from __future__ import annotations

from datetime import date
from typing import Callable

from boxmunge.cve.hardening import HardeningProfile, calculate_hardening_penalty
from boxmunge.cve.relevance import irrelevant_ecosystem
from boxmunge.cve.scanner import (
    AttackVector,
    Finding,
    ScanResult,
    Severity,
    VulnStatus,
    distro_severity,
)
from boxmunge.cve.policy_types import (
    _POSTURE_LABEL,
    _POSTURE_THRESHOLDS,
    _SEVERITY_RANK,
    Disposition,
    FindingDisposition,
    PolicyError,
    Posture,
    ProjectDecision,
    elevate_severity,
    parse_posture,
)
from boxmunge.cve.suppressions import Suppression, find_active_suppression
from boxmunge.cve.policy_explain import (
    explain_av_filter,
    explain_distro_deprioritized,
    explain_irrelevant_runtime,
    explain_kev_quarantine,
    explain_no_distro_verdict,
    explain_relaxed_kev_only,
    explain_threshold,
)

__all__ = [
    "Disposition",
    "FindingDisposition",
    "PolicyError",
    "Posture",
    "ProjectDecision",
    "elevate_severity",
    "evaluate_finding",
    "evaluate_project",
    "parse_posture",
]


def _kev_never(_cve: str) -> bool:
    """Default KEV predicate — nothing is known-exploited (keeps callers total)."""
    return False


# Distro statuses that mean "not an actionable/urgent fix" → informational
# below paranoid. END_OF_LIFE is deliberately excluded (more dangerous, not
# less — no fix will ever come), so it falls through to the threshold like
# AFFECTED.
_DEPRIORITIZED_STATUS: frozenset[VulnStatus] = frozenset({
    VulnStatus.WILL_NOT_FIX, VulnStatus.FIX_DEFERRED,
    VulnStatus.NOT_AFFECTED, VulnStatus.UNDER_INVESTIGATION,
})


# ---------- evaluation ----------


def _informational(
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


def _threshold_disposition(
    finding: Finding,
    base: Severity,
    effective: Severity,
    penalty: int,
    posture: Posture,
    *,
    compare_sev: Severity,
    dangerously_disable_quarantine: bool,
) -> FindingDisposition:
    """Compare `compare_sev` against the posture threshold and dispose.

    `effective` is what the operator sees on the disposition (the severity the
    decision was made on): NVD-effective under paranoid, distro-effective on a
    non-paranoid quarantine. `compare_sev` is the value actually compared.
    """
    threshold = _POSTURE_THRESHOLDS[posture]
    over = _SEVERITY_RANK[compare_sev] >= _SEVERITY_RANK[threshold]
    if over and dangerously_disable_quarantine:
        disposition = Disposition.STILL_RUNNING_AT_RISK
    elif over:
        disposition = Disposition.QUARANTINE
    else:
        disposition = Disposition.INFORMATIONAL
    return FindingDisposition(
        finding=finding,
        base_severity=base,
        hardening_penalty=penalty,
        effective_severity=effective,
        disposition=disposition,
        suppression=None,
        explanation=explain_threshold(
            base,
            effective,
            penalty,
            _POSTURE_LABEL[posture],
            threshold.value,
            over_threshold=over,
            dangerously_disabled=dangerously_disable_quarantine,
        ),
    )


def evaluate_finding(
    finding: Finding,
    *,
    posture: Posture,
    hardening_penalty: int,
    dangerously_disable_quarantine: bool,
    suppressions: tuple[Suppression, ...],
    today: date,
    kev_lookup: Callable[[str], bool] = _kev_never,
    runtimes: frozenset[str] | None = None,
) -> FindingDisposition:
    """Decide the disposition for a single finding (the trust ladder).

    Order of checks (see the module docstring for the rationale of each):
    fix → IGNORED_FIXED; KEV override → QUARANTINE; suppression → SUPPRESSED;
    UNKNOWN severity → INFORMATIONAL; paranoid → NVD threshold; relaxed →
    INFORMATIONAL (KEV-only, handled above); else (balanced/strict)
    irrelevant-runtime / distro-deprioritized / no-distro-verdict /
    non-network AV → INFORMATIONAL; else distro-severity threshold →
    QUARANTINE / STILL_RUNNING_AT_RISK / INFORMATIONAL.
    """
    base = finding.severity
    effective = elevate_severity(base, hardening_penalty)

    # 1. Upstream fix.
    if finding.fix_available:
        return FindingDisposition(
            finding=finding,
            base_severity=base,
            hardening_penalty=hardening_penalty,
            effective_severity=effective,
            disposition=Disposition.IGNORED_FIXED,
            suppression=None,
            explanation=(
                f"Fix available upstream ({finding.fixed_version}); "
                f"deferred to auto-update."
            ),
        )

    suppression = find_active_suppression(suppressions, finding.cve_id, today=today)

    # 2. KEV override — actively exploited, quarantine regardless of posture,
    # distro status, attack vector, threshold, or suppression (B-07).
    if kev_lookup(finding.cve_id):
        return FindingDisposition(
            finding=finding,
            base_severity=base,
            hardening_penalty=hardening_penalty,
            effective_severity=effective,
            disposition=Disposition.QUARANTINE,
            suppression=None,
            explanation=explain_kev_quarantine(
                finding.cve_id,
                suppression.until.isoformat() if suppression else None,
            ),
            kev_listed=True,
        )

    # 3. Active suppression.
    if suppression is not None:
        return FindingDisposition(
            finding=finding,
            base_severity=base,
            hardening_penalty=hardening_penalty,
            effective_severity=effective,
            disposition=Disposition.SUPPRESSED,
            suppression=suppression,
            explanation=(
                f"Suppressed by operator (until {suppression.until.isoformat()}, "
                f"reason: {suppression.reason})."
            ),
        )

    # 4. Unknown severity — report only.
    if base == Severity.UNKNOWN:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            "Unknown severity from scanner; reporting only.",
        )

    # 5. Paranoid: no distro trust, no AV filter — NVD severity vs. threshold
    # (byte-for-byte today's behavior).
    if posture is Posture.PARANOID:
        return _threshold_disposition(
            finding,
            base,
            effective,
            hardening_penalty,
            posture,
            compare_sev=effective,
            dangerously_disable_quarantine=dangerously_disable_quarantine,
        )

    # 6. Relaxed: KEV is the ONLY quarantine trigger (already handled at step
    # 3). Every non-KEV finding is informational regardless of distro
    # severity — the most hands-off tier, for operators who accept
    # severity-based risk.
    if posture is Posture.RELAXED:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_relaxed_kev_only(),
        )

    # 7. Package belongs to a language runtime this project never invokes.
    # Placed ahead of the distro-status gates: all produce INFORMATIONAL, so
    # ordering is behaviourally inert, but this reason is the most useful one
    # and — unlike the distro routes — it does not expire when Debian updates
    # its tracker. `None` means the caller opted out; the gate is skipped.
    if runtimes is not None:
        ecosystem = irrelevant_ecosystem(finding, runtimes=runtimes)
        if ecosystem is not None:
            return _informational(
                finding,
                base,
                hardening_penalty,
                effective,
                explain_irrelevant_runtime(
                    finding.package, ecosystem, runtimes,
                    _POSTURE_LABEL[posture],
                ),
            )

    # 8. Distro deprioritized → informational (the minizip fix).
    if finding.status in _DEPRIORITIZED_STATUS:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_distro_deprioritized(finding.status, distro_severity(finding)),
        )

    # 9. No distro verdict (only NVD/GHSA) → informational.
    distro_sev = distro_severity(finding)
    if distro_sev is None:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_no_distro_verdict(base),
        )

    # 10. v0.7.1 Attack Vector filter (retained) — non-paranoid, non-network.
    if finding.attack_vector is not AttackVector.NETWORK:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_av_filter(finding.attack_vector, _POSTURE_LABEL[posture]),
        )

    # 11. Threshold comparison against the DISTRO severity (elevated by the
    # hardening penalty). effective_severity now reflects the distro severity
    # the decision was actually made on. Reached only by balanced/strict with
    # a distro severity and a status outside _DEPRIORITIZED_STATUS (AFFECTED,
    # END_OF_LIFE, or UNKNOWN — a missing status fails closed).
    distro_effective = elevate_severity(distro_sev, hardening_penalty)
    return _threshold_disposition(
        finding,
        base,
        distro_effective,
        hardening_penalty,
        posture,
        compare_sev=distro_effective,
        dangerously_disable_quarantine=dangerously_disable_quarantine,
    )


def evaluate_project(
    project_name: str,
    scan_result: ScanResult,
    *,
    posture: Posture,
    hardening_profile: HardeningProfile,
    dangerously_disable_quarantine: bool,
    suppressions: tuple[Suppression, ...],
    today: date,
    kev_lookup: Callable[[str], bool] = _kev_never,
    runtimes: frozenset[str] | None = None,
) -> ProjectDecision:
    """Aggregate per-finding decisions into a project-level decision.

    The hardening penalty is computed once from the profile and threaded
    through every per-finding evaluation — one penalty per project, not
    per finding. Findings in the result are sorted by effective severity
    desc, then cve_id asc, for deterministic ordering downstream.
    """
    penalty = calculate_hardening_penalty(hardening_profile)

    dispositions = tuple(
        evaluate_finding(
            f,
            posture=posture,
            hardening_penalty=penalty,
            dangerously_disable_quarantine=dangerously_disable_quarantine,
            suppressions=suppressions,
            today=today,
            kev_lookup=kev_lookup,
            runtimes=runtimes,
        )
        for f in scan_result.findings
    )

    sorted_dispositions = tuple(
        sorted(
            dispositions,
            key=lambda d: (-_SEVERITY_RANK[d.effective_severity], d.finding.cve_id),
        )
    )

    quarantine_required = any(
        d.disposition == Disposition.QUARANTINE for d in sorted_dispositions
    )
    at_risk_running = any(
        d.disposition == Disposition.STILL_RUNNING_AT_RISK
        for d in sorted_dispositions
    )

    return ProjectDecision(
        project_name=project_name,
        image_ref=scan_result.image_ref,
        findings=sorted_dispositions,
        quarantine_required=quarantine_required,
        at_risk_running=at_risk_running,
        scanned_at=scan_result.scanned_at,
    )
