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

KEV is an override applied first (after fix/suppression): an actively
exploited CVE quarantines regardless of posture, distro status, attack
vector, or threshold. Below paranoid, a finding is otherwise routed to
INFORMATIONAL when the distro deprioritized it (status will_not_fix /
fix_deferred / not_affected / under_investigation), when there is no distro
verdict at all (only NVD/GHSA rated it), or when it fails the v0.7.1 Attack
Vector filter. Only the remaining distro-acknowledged, network-reachable
findings reach the severity threshold — compared against the *distro*
severity, elevated by the hardening penalty.

Effective severity = the severity the decision was made on, elevated by a
hardening penalty (capped at Critical). The penalty captures deviations from
the boxmunge overlay's hardened defaults — running with read_only disabled
means a Medium CVE behaves more like a High one in practice.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any, Callable

from boxmunge.cve.scanner import (
    AttackVector,
    Finding,
    ScanResult,
    Severity,
    VulnStatus,
    distro_severity,
)
from boxmunge.cve.suppressions import Suppression, find_active_suppression
from boxmunge.cve.policy_explain import (
    explain_av_filter,
    explain_distro_deprioritized,
    explain_kev_quarantine,
    explain_no_distro_verdict,
    explain_relaxed_kev_only,
    explain_threshold,
)


# ---------- enums and constants ----------


class Posture(Enum):
    """Operator-chosen security posture for a project."""

    RELAXED = "relaxed"
    BALANCED = "balanced"
    STRICT = "strict"
    PARANOID = "paranoid"


class Disposition(Enum):
    """Per-finding decision outcome."""

    IGNORED_FIXED = "ignored_fixed"
    SUPPRESSED = "suppressed"
    INFORMATIONAL = "informational"
    QUARANTINE = "quarantine"
    STILL_RUNNING_AT_RISK = "still_running_at_risk"


# Severity ordering for threshold comparison and penalty elevation.
# Re-declared here (rather than imported from scanner) so policy.py is
# decoupled from scanner internals — five entries, not worth coupling.
# UNKNOWN = 0 sorts last and is a no-op for elevation: we cannot raise
# something we don't recognize.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Inverse: rank-to-severity for elevation (skips UNKNOWN, which is a no-op).
_RANK_TO_SEVERITY: dict[int, Severity] = {
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}

# Posture → minimum effective severity that triggers quarantine.
# At-or-above the threshold quarantines (so balanced quarantines High AND
# Critical, not just above-High). PARANOID matches STRICT's Medium threshold
# but also bypasses the Attack Vector filter (see evaluate_finding).
_POSTURE_THRESHOLDS: dict[Posture, Severity] = {
    Posture.RELAXED: Severity.CRITICAL,
    Posture.BALANCED: Severity.HIGH,
    Posture.STRICT: Severity.MEDIUM,
    Posture.PARANOID: Severity.MEDIUM,
}

# Human label for posture in explanation strings — lowercase for prose flow.
_POSTURE_LABEL: dict[Posture, str] = {
    Posture.RELAXED: "relaxed",
    Posture.BALANCED: "balanced",
    Posture.STRICT: "strict",
    Posture.PARANOID: "paranoid",
}

_MAX_HARDENING_PENALTY = 2


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


# ---------- exceptions ----------


# Inherits ValueError so callers that catch ValueError on bad config
# (the conventional Python boundary error) also catch this.
class PolicyError(ValueError):
    """Policy input is invalid (typically a bad posture string)."""


# ---------- value types ----------


@dataclass(frozen=True)
class HardeningProfile:
    """Compose-derived hardening posture for a project.

    Captures the user's deviations from the boxmunge overlay's hardened
    baseline, after the overlay has been merged. v0.8 overlay enforces
    read_only=true, no-new-privileges=true, tmpfs:['/tmp'], and an empty
    cap_add by default — fields here are True iff the *applied* config
    still meets that baseline (read_only and no_new_privileges) or False
    if user config overrode it (extra_caps_added, privileged, or an
    explicit read_only:false in user compose).
    """

    read_only: bool
    no_new_privileges: bool
    extra_caps_added: bool
    privileged: bool


@dataclass(frozen=True)
class FindingDisposition:
    """Per-finding decision."""

    finding: Finding
    base_severity: Severity
    hardening_penalty: int
    effective_severity: Severity
    disposition: Disposition
    suppression: Suppression | None
    explanation: str


@dataclass(frozen=True)
class ProjectDecision:
    """Project-wide decision aggregated from per-finding dispositions."""

    project_name: str
    image_ref: str
    findings: tuple[FindingDisposition, ...]
    quarantine_required: bool
    at_risk_running: bool
    scanned_at: datetime


# ---------- pure helpers ----------


def calculate_hardening_penalty(profile: HardeningProfile) -> int:
    """Sum of step-elevations from the hardened default, capped at +2.

    +1 each for read_only disabled, no_new_privileges disabled, extra
    cap_add. +2 outright for privileged (validators block this upstream;
    we still tolerate it gracefully so the engine is total).
    """
    if profile.privileged:
        return _MAX_HARDENING_PENALTY

    penalty = 0
    if not profile.read_only:
        penalty += 1
    if not profile.no_new_privileges:
        penalty += 1
    if profile.extra_caps_added:
        penalty += 1
    return min(penalty, _MAX_HARDENING_PENALTY)


def elevate_severity(base: Severity, penalty: int) -> Severity:
    """Apply `penalty` steps of elevation to `base`, capped at CRITICAL.

    UNKNOWN is a no-op: the engine has no confident floor to elevate from.
    """
    if base == Severity.UNKNOWN:
        return Severity.UNKNOWN
    elevated_rank = min(_SEVERITY_RANK[base] + penalty, _SEVERITY_RANK[Severity.CRITICAL])
    return _RANK_TO_SEVERITY[elevated_rank]


def parse_posture(value: str | None) -> Posture:
    """Parse a posture string (case-insensitive). None → BALANCED.

    This is a defensive boundary: schema validation has already happened
    upstream by the time policy.py sees the value. Internal callers
    construct Posture enums directly.

    Raises PolicyError (a ValueError subclass) on unrecognized values.
    """
    if value is None:
        return Posture.BALANCED
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"posture must be a non-empty string, got {value!r}")
    normalized = value.strip().lower()
    for posture in Posture:
        if posture.value == normalized:
            return posture
    valid = ", ".join(p.value for p in Posture)
    raise PolicyError(f"unknown posture {value!r}; expected one of: {valid}")


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
) -> FindingDisposition:
    """Decide the disposition for a single finding (the trust ladder).

    Order of checks (see the module docstring for the rationale of each):
    fix → IGNORED_FIXED; suppression → SUPPRESSED; KEV override → QUARANTINE;
    UNKNOWN severity → INFORMATIONAL; paranoid → NVD threshold; relaxed →
    INFORMATIONAL (KEV-only, handled above); else (balanced/strict)
    distro-deprioritized / no-distro-verdict / non-network AV → INFORMATIONAL;
    else distro-severity threshold → QUARANTINE / STILL_RUNNING_AT_RISK /
    INFORMATIONAL.
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

    # 2. Active suppression.
    suppression = find_active_suppression(suppressions, finding.cve_id, today=today)
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

    # 3. KEV override — actively exploited, quarantine regardless of posture,
    # distro status, attack vector, or threshold.
    if kev_lookup(finding.cve_id):
        return FindingDisposition(
            finding=finding,
            base_severity=base,
            hardening_penalty=hardening_penalty,
            effective_severity=effective,
            disposition=Disposition.QUARANTINE,
            suppression=None,
            explanation=explain_kev_quarantine(finding.cve_id),
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

    # 7. Distro deprioritized → informational (the minizip fix).
    if finding.status in _DEPRIORITIZED_STATUS:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_distro_deprioritized(finding.status, distro_severity(finding)),
        )

    # 8. No distro verdict (only NVD/GHSA) → informational.
    distro_sev = distro_severity(finding)
    if distro_sev is None:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_no_distro_verdict(base),
        )

    # 9. v0.7.1 Attack Vector filter (retained) — non-paranoid, non-network.
    if finding.attack_vector is not AttackVector.NETWORK:
        return _informational(
            finding,
            base,
            hardening_penalty,
            effective,
            explain_av_filter(finding.attack_vector, _POSTURE_LABEL[posture]),
        )

    # 10. Threshold comparison against the DISTRO severity (elevated by the
    # hardening penalty). effective_severity now reflects the distro severity
    # the decision was actually made on. Reached only by balanced/strict with
    # status ∈ {AFFECTED, END_OF_LIFE} and a distro severity.
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


# ---------- compose extraction ----------


def hardening_profile_from_compose(
    compose: dict[str, Any],
    *,
    services_with_overlay: set[str] | None = None,
) -> HardeningProfile:
    """Extract the project's effective hardening profile from a parsed compose.yml.

    The project-level profile is the worst-case (most weakened) across all
    services — if any single service has read_only=False, the project's
    effective hardening is read_only=False. This matches the operator's
    risk model: a single weakened service exposes the project's blast radius.

    Reads the user's compose.yml — i.e. pre-overlay-merge. Boxmunge's overlay
    enforces hardening by default; this function captures user *deviations*
    from that baseline.

    `services_with_overlay`: services where boxmunge's hardening overlay is
    active (every service whose effective profile is not "off"). For these
    services we treat `no-new-privileges` AND `read_only` as enforced by the
    overlay even if the user's compose doesn't declare them explicitly — the
    overlay sets both (v0.8 made read_only a default), and `compose_validate`
    rejects user attempts to flip no-new-privileges back via
    `no-new-privileges:false`. If the user declares `read_only: false`
    explicitly, that wins (the v0.8 overlay generator omits its own
    read_only fragment for that service), so it correctly weakens the
    profile here. If `None` (default), assume every service has the
    overlay applied — backward-compatible with callers that haven't been
    updated and matches the common case for new deployments.

    `cap_add` is always user-driven and judged on the literal compose
    declaration regardless of overlay.

    For each service:
      - read_only: True iff overlay applies AND user did NOT declare
        `read_only: false`, OR (no overlay) `read_only: true` is explicitly set
      - no_new_privileges: True iff overlay applies OR (`security_opt`
        contains "no-new-privileges:true" AND no entry contains
        "no-new-privileges:false")
      - extra_caps_added: True iff `cap_add` is non-empty
      - privileged: True iff `privileged: true`

    Project-level: AND across services for the True-required fields, OR for
    the True-bad fields. With zero services we vacuously return a fully-
    hardened profile — there's nothing to scan, so policy is moot.
    """
    services = compose.get("services") or {}
    if not isinstance(services, dict) or not services:
        return HardeningProfile(
            read_only=True,
            no_new_privileges=True,
            extra_caps_added=False,
            privileged=False,
        )

    # When None, default to "every service has overlay applied" — every named
    # service is in the assumed set.
    overlay_set: set[str] = (
        services_with_overlay
        if services_with_overlay is not None
        else set(services.keys())
    )

    project_read_only = True
    project_no_new_privileges = True
    project_extra_caps_added = False
    project_privileged = False

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        # read_only — v0.8: overlay enforces read-only rootfs by default for
        # non-off services. The only thing that weakens this is an explicit
        # `read_only: false` in user compose (the overlay generator omits
        # its read_only fragment when the user declared anything for that
        # field, and Compose merge gives us the user's literal value).
        # For off-profile services (no overlay), only an explicit
        # `read_only: true` counts.
        if svc_name in overlay_set:
            svc_ro = svc.get("read_only") is not False
        else:
            svc_ro = svc.get("read_only") is True
        if not svc_ro:
            project_read_only = False

        # no_new_privileges — overlay enforces it for non-off services.
        # Otherwise, fall back to literal compose declaration.
        if svc_name in overlay_set:
            svc_nnp = True
        else:
            sec_opt = svc.get("security_opt") or []
            if not isinstance(sec_opt, list):
                sec_opt = []
            has_true = any(s == "no-new-privileges:true" for s in sec_opt)
            has_false = any(s == "no-new-privileges:false" for s in sec_opt)
            svc_nnp = has_true and not has_false
        if not svc_nnp:
            project_no_new_privileges = False

        # extra_caps_added — any non-empty cap_add list weakens. Overlay's
        # cap_drop is extended (not replaced) by user cap_add, so a user
        # cap_add really does relax the profile.
        cap_add = svc.get("cap_add") or []
        if isinstance(cap_add, list) and len(cap_add) > 0:
            project_extra_caps_added = True

        # privileged — any True weakens. Already rejected by compose_validate
        # on non-off services, but tolerated here for tests / off-profile.
        if svc.get("privileged") is True:
            project_privileged = True

    return HardeningProfile(
        read_only=project_read_only,
        no_new_privileges=project_no_new_privileges,
        extra_caps_added=project_extra_caps_added,
        privileged=project_privileged,
    )
