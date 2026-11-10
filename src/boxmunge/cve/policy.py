# SPDX-License-Identifier: Apache-2.0
"""CVE policy decision engine — pure-function gate over scan findings.

Inputs: scan findings, project posture, hardening profile, suppressions.
Output: a structured decision per finding, aggregated to a project decision.

This module is deliberately I/O-free: callers (cron job, deploy gate, CLI)
are responsible for the actions implied by a decision (quarantine, alert,
audit-log append). The split keeps the decision logic deterministic and
unit-testable, and lets the same engine drive scheduled scans and
ad-hoc CLI inspection from one source of truth.

The trust ladder — what each posture accepts downtime for (non-paranoid
postures trust the distro's own triage):
    relaxed  → quarantine only on an unfixed CISA KEV (actively exploited)
               finding; a fixable one is alerted every scan.
    balanced → quarantine only on CISA KEV, fixable or not. A distro
               status:affected + distro severity ≥ High + AV:N finding with
               no fix is AWAITING_FIX: alerted once, never downtime.
    strict   → KEV OR distro status:affected + distro severity ≥ Medium + AV:N.
    paranoid → anything ≥ Medium over threshold; no distro trust, no AV
               filter, the highest severity any source reports (NVD, the
               distro, GHSA, ...). KEV can still escalate.

KEV is the first gate: an actively exploited CVE quarantines regardless of
posture, distro status, attack vector, threshold, an operator suppression
(a suppression reviewed before the CVE was known to be exploited must not
keep hiding it — audit B-07), or an upstream fix the image is not running
(audit B-01). Under relaxed a fixable KEV finding stays up and is alerted
on every scan instead. dangerously_disable_quarantine is honoured for KEV
too (STILL_RUNNING_AT_RISK, alerted every scan — audit B-09).

Below paranoid, a finding is otherwise routed to INFORMATIONAL when the
distro deprioritized it (status will_not_fix / fix_deferred / not_affected /
under_investigation), when there is no distro verdict at all (only NVD/GHSA
rated it), or when it fails the v0.7.1 Attack Vector filter. Only the
remaining distro-acknowledged, network-reachable findings reach the severity
gate — compared against the *distro* severity, elevated by the hardening
penalty. Meeting it quarantines under strict and alerts (AWAITING_FIX) under
balanced, so under balanced and relaxed the penalty never decides downtime.

A finding is also routed to INFORMATIONAL — below paranoid — when its
package belongs to a language runtime the project does not use (a Perl bug
cannot run in a Python-only image). This gate consults only
positively-identified runtime families, so ordinary system libraries such
as openssl remain quarantinable.

Paranoid's severity is the highest any source reports, so neither the
distro's triage nor a lower NVD rating can relax it: NVD Critical over a
distro Low is Critical (audit B-08), and paranoid never decides on a lower
severity than strict does. With no NVD rating the other sources still
count; with no rating from any source the finding is UNKNOWN (step 4).

Effective severity = the severity the decision was made on, elevated by a
hardening penalty (capped at Critical). The penalty captures deviations from
the boxmunge overlay's hardened defaults — running with read_only disabled
means a Medium CVE behaves more like a High one in practice.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import Callable

from boxmunge.cve.hardening import (
    HardeningProfile, UpcomingHardening, calculate_hardening_penalty,
)
from boxmunge.cve.hardening_upcoming import flag_upcoming
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
    Disposition,
    FindingDisposition,
    PolicyError,
    Posture,
    ProjectDecision,
    elevate_severity,
    parse_posture,
    severity_gate_quarantines,
)
from boxmunge.cve.policy_gates import (
    informational,
    paranoid_severity,
    threshold_disposition,
)
from boxmunge.cve.suppressions import Suppression, find_active_suppression
from boxmunge.cve.policy_explain import (
    explain_av_filter,
    explain_distro_deprioritized,
    explain_fix_available,
    explain_kev_fix_not_running,
    explain_kev_opted_out,
    explain_irrelevant_runtime,
    explain_kev_quarantine,
    explain_no_distro_verdict,
    explain_relaxed_kev_only,
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
    "severity_gate_quarantines",
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
    KEV override → QUARANTINE (fixable KEV under relaxed → IGNORED_FIXED);
    fix → IGNORED_FIXED; suppression → SUPPRESSED;
    UNKNOWN severity → INFORMATIONAL; paranoid → highest-rating threshold; relaxed →
    INFORMATIONAL (KEV-only, handled above); else (balanced/strict)
    irrelevant-runtime / distro-deprioritized / no-distro-verdict /
    non-network AV → INFORMATIONAL; else distro-severity gate → strict:
    QUARANTINE / STILL_RUNNING_AT_RISK, balanced: AWAITING_FIX; below it
    INFORMATIONAL.
    """
    if posture is Posture.PARANOID:
        base, sources = paranoid_severity(finding)
    else:
        base, sources = finding.severity, ()
    effective = elevate_severity(base, hardening_penalty)

    suppression = find_active_suppression(suppressions, finding.cve_id, today=today)

    # 1. KEV override — actively exploited, quarantine regardless of posture,
    # distro status, attack vector, threshold, suppression (B-07), or a fix
    # that exists but is not running (B-01). Relaxed is the one exception
    # for a fixable KEV finding: it stays up and is alerted every scan.
    # Under balanced this is the ONLY route to a quarantine.
    if kev_lookup(finding.cve_id):
        fix = finding.fixed_version if finding.fix_available else None
        if dangerously_disable_quarantine:
            # The documented opt-out is honoured for KEV too (B-09); it is
            # never silent: the at-risk KEV alert repeats every scan.
            return FindingDisposition(
                finding=finding, base_severity=base,
                hardening_penalty=hardening_penalty, effective_severity=effective,
                disposition=Disposition.STILL_RUNNING_AT_RISK, suppression=None,
                explanation=explain_kev_opted_out(finding.cve_id, fix),
                kev_listed=True,
            )
        if fix is not None and posture is Posture.RELAXED:
            return FindingDisposition(
                finding=finding, base_severity=base,
                hardening_penalty=hardening_penalty, effective_severity=effective,
                disposition=Disposition.IGNORED_FIXED, suppression=None,
                explanation=explain_kev_fix_not_running(finding.cve_id, fix),
                kev_listed=True,
            )
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
                fix,
            ),
            kev_listed=True,
        )

    # 2. Upstream fix (not KEV): IGNORED_FIXED, flagged when the finding
    # would otherwise meet the gate (quarantine, at risk, or balanced's
    # AWAITING_FIX) so it is alerted with the rebuild advice, never silently
    # ignored (B-01). The but-for evaluation is the same pure function.
    if finding.fix_available:
        but_for = evaluate_finding(
            replace(finding, fixed_version=None), posture=posture,
            hardening_penalty=hardening_penalty,
            dangerously_disable_quarantine=dangerously_disable_quarantine,
            suppressions=suppressions, today=today, kev_lookup=kev_lookup,
            runtimes=runtimes,
        ).disposition
        would = but_for in (Disposition.QUARANTINE, Disposition.STILL_RUNNING_AT_RISK,
                            Disposition.AWAITING_FIX)
        return FindingDisposition(
            finding=finding,
            base_severity=base,
            hardening_penalty=hardening_penalty,
            effective_severity=effective,
            disposition=Disposition.IGNORED_FIXED,
            suppression=None,
            explanation=explain_fix_available(
                finding.fixed_version, meets_gate=would,
                gate_quarantines=but_for is not Disposition.AWAITING_FIX,
                posture_label=_POSTURE_LABEL[posture],
            ),
            fix_would_quarantine=would,
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
        return informational(
            finding,
            base,
            hardening_penalty,
            effective,
            "Unknown severity from scanner; reporting only.",
        )

    # 5. Paranoid: no distro trust, no AV filter — the highest severity any
    # source reports vs. threshold.
    if posture is Posture.PARANOID:
        return threshold_disposition(
            finding,
            base,
            effective,
            hardening_penalty,
            posture,
            compare_sev=effective,
            dangerously_disable_quarantine=dangerously_disable_quarantine,
            severity_sources=sources,
        )

    # 6. Relaxed: KEV is the ONLY quarantine trigger (already handled at step
    # 1). Every non-KEV finding is informational regardless of distro
    # severity — the most hands-off tier, for operators who accept
    # severity-based risk.
    if posture is Posture.RELAXED:
        return informational(
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
            return informational(
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
        return informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_distro_deprioritized(finding.status, distro_severity(finding)),
        )

    # 9. No distro verdict (only NVD/GHSA) → informational.
    distro_sev = distro_severity(finding)
    if distro_sev is None:
        return informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_no_distro_verdict(base),
        )

    # 10. v0.7.1 Attack Vector filter (retained) — non-paranoid, non-network.
    if finding.attack_vector is not AttackVector.NETWORK:
        return informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_av_filter(finding.attack_vector, _POSTURE_LABEL[posture]),
        )

    # 11. Severity gate against the DISTRO severity (elevated by the hardening
    # penalty). effective_severity now reflects the distro severity the
    # decision was actually made on. Reached only by balanced/strict with a
    # distro severity and a status outside _DEPRIORITIZED_STATUS (AFFECTED,
    # END_OF_LIFE, or UNKNOWN — a missing status fails closed). Strict's gate
    # quarantines; balanced's alerts (AWAITING_FIX).
    distro_effective = elevate_severity(distro_sev, hardening_penalty)
    return threshold_disposition(
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
    upcoming: UpcomingHardening | None = None,
) -> ProjectDecision:
    """Aggregate per-finding decisions into a project-level decision.

    The hardening penalty is computed once from the profile and threaded
    through every per-finding evaluation — one penalty per project, not
    per finding. Findings in the result are sorted by effective severity
    desc, then cve_id asc, for deterministic ordering downstream.

    ``upcoming`` is the stricter hardening the policy will apply from 0.12.
    A finding that does not quarantine under ``hardening_profile`` but would
    under it keeps its disposition and is flagged hardening_would_quarantine:
    a warning, never a quarantine. Only a posture whose severity gate
    quarantines (strict, paranoid) is judged under it: under relaxed and
    balanced the penalty decides no quarantine, so there is nothing to warn of.
    """
    penalty = calculate_hardening_penalty(hardening_profile)

    def judge(f: Finding, hardening_penalty: int) -> FindingDisposition:
        return evaluate_finding(
            f,
            posture=posture,
            hardening_penalty=hardening_penalty,
            dangerously_disable_quarantine=dangerously_disable_quarantine,
            suppressions=suppressions,
            today=today,
            kev_lookup=kev_lookup,
            runtimes=runtimes,
        )

    dispositions = tuple(judge(f, penalty) for f in scan_result.findings)
    if upcoming is not None and severity_gate_quarantines(posture):
        upcoming_penalty = calculate_hardening_penalty(upcoming.profile)
        dispositions = tuple(
            flag_upcoming(d, judge(d.finding, upcoming_penalty), upcoming)
            for d in dispositions
        )

    sorted_dispositions = tuple(
        sorted(
            dispositions,
            key=lambda d: (-d.effective_severity.rank, d.finding.cve_id),
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
