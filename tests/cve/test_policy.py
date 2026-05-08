"""Tests for boxmunge.cve.policy — the policy decision engine."""

from datetime import date, datetime, timezone

import pytest

from boxmunge.cve.scanner import AttackVector, Finding, ScanResult, Severity
from boxmunge.cve.suppressions import Suppression
from boxmunge.cve.policy import (
    Disposition,
    HardeningProfile,
    PolicyError,
    Posture,
    ProjectDecision,
    _POSTURE_THRESHOLDS,
    calculate_hardening_penalty,
    elevate_severity,
    evaluate_finding,
    evaluate_project,
    hardening_profile_from_compose,
    parse_posture,
)


# ---------- helpers ----------


_TODAY = date(2026, 5, 6)


def _finding(
    cve_id: str = "CVE-2026-0001",
    severity: Severity = Severity.HIGH,
    fixed_version: str | None = None,
    package: str = "openssl",
    installed_version: str = "1.1.1k",
    title: str = "Some vulnerability",
    primary_url: str | None = None,
    attack_vector: AttackVector | None = AttackVector.NETWORK,
) -> Finding:
    # Default to AV:NETWORK so existing posture/threshold tests aren't gated
    # out by the v0.7.1 AV filter. Tests that care about the AV filter set
    # attack_vector explicitly.
    return Finding(
        cve_id=cve_id,
        severity=severity,
        package=package,
        installed_version=installed_version,
        fixed_version=fixed_version,
        title=title,
        primary_url=primary_url,
        attack_vector=attack_vector,
    )


def _profile(
    *,
    read_only: bool = True,
    no_new_privileges: bool = True,
    extra_caps_added: bool = False,
    privileged: bool = False,
) -> HardeningProfile:
    return HardeningProfile(
        read_only=read_only,
        no_new_privileges=no_new_privileges,
        extra_caps_added=extra_caps_added,
        privileged=privileged,
    )


def _suppression(
    cve_id: str = "CVE-2026-0001",
    until: date = date(2027, 1, 1),
) -> Suppression:
    return Suppression(
        cve_id=cve_id,
        until=until,
        reason="Reviewed",
        reviewed_by="jon",
        added=date(2026, 5, 6),
    )


# ---------- calculate_hardening_penalty ----------


def test_penalty_default_profile_is_zero() -> None:
    assert calculate_hardening_penalty(_profile()) == 0


def test_penalty_read_only_disabled_adds_one() -> None:
    assert calculate_hardening_penalty(_profile(read_only=False)) == 1


def test_penalty_no_new_privileges_disabled_adds_one() -> None:
    assert calculate_hardening_penalty(_profile(no_new_privileges=False)) == 1


def test_penalty_extra_caps_adds_one() -> None:
    assert calculate_hardening_penalty(_profile(extra_caps_added=True)) == 1


def test_penalty_three_deviations_caps_at_two() -> None:
    profile = _profile(
        read_only=False, no_new_privileges=False, extra_caps_added=True,
    )
    assert calculate_hardening_penalty(profile) == 2


def test_penalty_privileged_alone_is_two() -> None:
    assert calculate_hardening_penalty(_profile(privileged=True)) == 2


def test_penalty_privileged_plus_other_caps_at_two() -> None:
    profile = _profile(privileged=True, read_only=False)
    assert calculate_hardening_penalty(profile) == 2


# ---------- elevate_severity ----------


@pytest.mark.parametrize(
    "base, penalty, expected",
    [
        (Severity.LOW, 0, Severity.LOW),
        (Severity.LOW, 1, Severity.MEDIUM),
        (Severity.LOW, 2, Severity.HIGH),
        (Severity.MEDIUM, 2, Severity.CRITICAL),
        (Severity.HIGH, 1, Severity.CRITICAL),
        (Severity.HIGH, 2, Severity.CRITICAL),
        (Severity.CRITICAL, 1, Severity.CRITICAL),
        (Severity.CRITICAL, 2, Severity.CRITICAL),
        (Severity.UNKNOWN, 0, Severity.UNKNOWN),
        (Severity.UNKNOWN, 1, Severity.UNKNOWN),
        (Severity.UNKNOWN, 2, Severity.UNKNOWN),
    ],
)
def test_elevate_severity(
    base: Severity, penalty: int, expected: Severity,
) -> None:
    assert elevate_severity(base, penalty) == expected


# ---------- evaluate_finding: short-circuits ----------


def test_fix_available_returns_ignored_fixed_regardless_of_severity() -> None:
    finding = _finding(severity=Severity.CRITICAL, fixed_version="1.2.3")
    decision = evaluate_finding(
        finding,
        posture=Posture.STRICT,
        hardening_penalty=2,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.IGNORED_FIXED
    assert "1.2.3" in decision.explanation


def test_fix_available_takes_priority_over_active_suppression() -> None:
    finding = _finding(severity=Severity.CRITICAL, fixed_version="1.2.3")
    decision = evaluate_finding(
        finding,
        posture=Posture.STRICT,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(_suppression(cve_id=finding.cve_id),),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.IGNORED_FIXED


def test_active_suppression_returns_suppressed() -> None:
    finding = _finding(severity=Severity.CRITICAL)
    sup = _suppression(cve_id=finding.cve_id)
    decision = evaluate_finding(
        finding,
        posture=Posture.STRICT,
        hardening_penalty=2,
        dangerously_disable_quarantine=False,
        suppressions=(sup,),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.SUPPRESSED
    assert decision.suppression is sup
    assert "Suppressed" in decision.explanation


def test_suppression_for_other_cve_falls_through() -> None:
    finding = _finding(cve_id="CVE-2026-0001", severity=Severity.HIGH)
    sup = _suppression(cve_id="CVE-2026-9999")
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(sup,),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.QUARANTINE
    assert decision.suppression is None


def test_expired_suppression_falls_through() -> None:
    finding = _finding(severity=Severity.HIGH)
    sup = _suppression(cve_id=finding.cve_id, until=date(2025, 1, 1))
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(sup,),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.QUARANTINE


def test_unknown_severity_is_informational() -> None:
    finding = _finding(severity=Severity.UNKNOWN)
    decision = evaluate_finding(
        finding,
        posture=Posture.STRICT,
        hardening_penalty=2,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.INFORMATIONAL
    assert "Unknown" in decision.explanation or "unknown" in decision.explanation


# ---------- evaluate_finding: posture threshold matrix ----------


@pytest.mark.parametrize(
    "posture, severity, expected",
    [
        # RELAXED: only Critical quarantines
        (Posture.RELAXED, Severity.CRITICAL, Disposition.QUARANTINE),
        (Posture.RELAXED, Severity.HIGH, Disposition.INFORMATIONAL),
        (Posture.RELAXED, Severity.MEDIUM, Disposition.INFORMATIONAL),
        (Posture.RELAXED, Severity.LOW, Disposition.INFORMATIONAL),
        # BALANCED: High and above quarantine
        (Posture.BALANCED, Severity.CRITICAL, Disposition.QUARANTINE),
        (Posture.BALANCED, Severity.HIGH, Disposition.QUARANTINE),
        (Posture.BALANCED, Severity.MEDIUM, Disposition.INFORMATIONAL),
        (Posture.BALANCED, Severity.LOW, Disposition.INFORMATIONAL),
        # STRICT: Medium and above quarantine
        (Posture.STRICT, Severity.CRITICAL, Disposition.QUARANTINE),
        (Posture.STRICT, Severity.HIGH, Disposition.QUARANTINE),
        (Posture.STRICT, Severity.MEDIUM, Disposition.QUARANTINE),
        (Posture.STRICT, Severity.LOW, Disposition.INFORMATIONAL),
    ],
)
def test_posture_threshold_matrix(
    posture: Posture, severity: Severity, expected: Disposition,
) -> None:
    finding = _finding(severity=severity)
    decision = evaluate_finding(
        finding,
        posture=posture,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == expected


# ---------- evaluate_finding: dangerously_disable_quarantine ----------


def test_would_quarantine_with_dangerously_disabled_becomes_at_risk() -> None:
    finding = _finding(severity=Severity.CRITICAL)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=0,
        dangerously_disable_quarantine=True,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.STILL_RUNNING_AT_RISK


def test_would_quarantine_without_dangerously_quarantines() -> None:
    finding = _finding(severity=Severity.CRITICAL)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.QUARANTINE


def test_below_threshold_with_dangerously_still_informational() -> None:
    finding = _finding(severity=Severity.LOW)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=0,
        dangerously_disable_quarantine=True,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.INFORMATIONAL


# ---------- evaluate_finding: hardening penalty elevation ----------


def test_balanced_medium_with_penalty_one_elevates_to_quarantine() -> None:
    finding = _finding(severity=Severity.MEDIUM)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=1,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.effective_severity == Severity.HIGH
    assert decision.disposition == Disposition.QUARANTINE
    assert decision.hardening_penalty == 1


def test_balanced_low_with_penalty_two_elevates_to_quarantine() -> None:
    finding = _finding(severity=Severity.LOW)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=2,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.effective_severity == Severity.HIGH
    assert decision.disposition == Disposition.QUARANTINE


def test_strict_low_with_penalty_one_elevates_to_quarantine() -> None:
    finding = _finding(severity=Severity.LOW)
    decision = evaluate_finding(
        finding,
        posture=Posture.STRICT,
        hardening_penalty=1,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.effective_severity == Severity.MEDIUM
    assert decision.disposition == Disposition.QUARANTINE


def test_relaxed_low_with_penalty_two_still_below_critical() -> None:
    finding = _finding(severity=Severity.LOW)
    decision = evaluate_finding(
        finding,
        posture=Posture.RELAXED,
        hardening_penalty=2,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.effective_severity == Severity.HIGH
    assert decision.disposition == Disposition.INFORMATIONAL


# ---------- evaluate_finding: misc field assertions ----------


def test_finding_disposition_carries_base_severity() -> None:
    finding = _finding(severity=Severity.MEDIUM)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=1,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.base_severity == Severity.MEDIUM
    assert decision.finding is finding
    assert decision.suppression is None


# ---------- evaluate_project ----------


def _scan_result(
    findings: tuple[Finding, ...],
    image_ref: str = "myapp:1.2.3",
) -> ScanResult:
    return ScanResult(
        image_ref=image_ref,
        findings=findings,
        scanned_at=datetime(2026, 5, 6, 12, 0, 0, tzinfo=timezone.utc),
        db_version="2026-05-06T00:00:00Z",
    )


def test_project_decision_mixed_findings() -> None:
    findings = (
        _finding(cve_id="CVE-2026-0001", severity=Severity.CRITICAL),
        _finding(cve_id="CVE-2026-0002", severity=Severity.HIGH, fixed_version="2.0"),
        _finding(cve_id="CVE-2026-0003", severity=Severity.LOW),
    )
    decision = evaluate_project(
        "myproj",
        _scan_result(findings),
        posture=Posture.BALANCED,
        hardening_profile=_profile(),
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert isinstance(decision, ProjectDecision)
    assert decision.project_name == "myproj"
    assert decision.image_ref == "myapp:1.2.3"
    assert decision.quarantine_required is True
    assert decision.at_risk_running is False
    assert len(decision.findings) == 3


def test_project_all_findings_have_fixes_no_quarantine() -> None:
    findings = (
        _finding(cve_id="CVE-2026-0001", severity=Severity.CRITICAL, fixed_version="1.0"),
        _finding(cve_id="CVE-2026-0002", severity=Severity.HIGH, fixed_version="2.0"),
    )
    decision = evaluate_project(
        "myproj",
        _scan_result(findings),
        posture=Posture.STRICT,
        hardening_profile=_profile(),
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.quarantine_required is False
    assert decision.at_risk_running is False
    assert all(d.disposition == Disposition.IGNORED_FIXED for d in decision.findings)


def test_project_critical_with_dangerously_marks_at_risk() -> None:
    findings = (
        _finding(cve_id="CVE-2026-0001", severity=Severity.CRITICAL),
    )
    decision = evaluate_project(
        "myproj",
        _scan_result(findings),
        posture=Posture.BALANCED,
        hardening_profile=_profile(),
        dangerously_disable_quarantine=True,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.quarantine_required is False
    assert decision.at_risk_running is True


def test_project_empty_scan() -> None:
    decision = evaluate_project(
        "myproj",
        _scan_result(()),
        posture=Posture.STRICT,
        hardening_profile=_profile(),
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.findings == ()
    assert decision.quarantine_required is False
    assert decision.at_risk_running is False


def test_project_findings_sorted_severity_desc_then_cve_asc() -> None:
    findings = (
        _finding(cve_id="CVE-2026-0009", severity=Severity.LOW),
        _finding(cve_id="CVE-2026-0001", severity=Severity.CRITICAL),
        _finding(cve_id="CVE-2026-0005", severity=Severity.HIGH),
        _finding(cve_id="CVE-2026-0002", severity=Severity.CRITICAL),
        _finding(cve_id="CVE-2026-0007", severity=Severity.MEDIUM),
    )
    decision = evaluate_project(
        "myproj",
        _scan_result(findings),
        posture=Posture.BALANCED,
        hardening_profile=_profile(),
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    cve_order = [d.finding.cve_id for d in decision.findings]
    assert cve_order == [
        "CVE-2026-0001",  # Critical
        "CVE-2026-0002",  # Critical
        "CVE-2026-0005",  # High
        "CVE-2026-0007",  # Medium
        "CVE-2026-0009",  # Low
    ]


def test_project_propagates_scanned_at() -> None:
    findings = (_finding(severity=Severity.LOW),)
    sr = _scan_result(findings)
    decision = evaluate_project(
        "myproj",
        sr,
        posture=Posture.BALANCED,
        hardening_profile=_profile(),
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.scanned_at == sr.scanned_at


def test_project_with_hardening_profile_elevates_findings() -> None:
    """A profile with read_only=False elevates Medium → High under BALANCED."""
    findings = (
        _finding(cve_id="CVE-2026-0001", severity=Severity.MEDIUM),
    )
    decision = evaluate_project(
        "myproj",
        _scan_result(findings),
        posture=Posture.BALANCED,
        hardening_profile=_profile(read_only=False),
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.findings[0].hardening_penalty == 1
    assert decision.findings[0].effective_severity == Severity.HIGH
    assert decision.quarantine_required is True


# ---------- v0.7.1 Attack Vector filter ----------


@pytest.mark.parametrize(
    "av, posture, severity, expected",
    [
        # AV:L under non-paranoid postures → INFORMATIONAL regardless of severity
        (AttackVector.LOCAL, Posture.BALANCED, Severity.HIGH, Disposition.INFORMATIONAL),
        (AttackVector.LOCAL, Posture.BALANCED, Severity.CRITICAL, Disposition.INFORMATIONAL),
        (AttackVector.LOCAL, Posture.STRICT, Severity.MEDIUM, Disposition.INFORMATIONAL),
        (AttackVector.LOCAL, Posture.RELAXED, Severity.CRITICAL, Disposition.INFORMATIONAL),
        # AV:Adjacent and AV:Physical also gated out under non-paranoid
        (AttackVector.ADJACENT, Posture.BALANCED, Severity.HIGH, Disposition.INFORMATIONAL),
        (AttackVector.PHYSICAL, Posture.BALANCED, Severity.CRITICAL, Disposition.INFORMATIONAL),
        # AV unknown (None) treated like AV:L under non-paranoid
        (None, Posture.BALANCED, Severity.HIGH, Disposition.INFORMATIONAL),
        (None, Posture.STRICT, Severity.MEDIUM, Disposition.INFORMATIONAL),
        # AV:N under non-paranoid → goes through the threshold gate normally
        (AttackVector.NETWORK, Posture.BALANCED, Severity.HIGH, Disposition.QUARANTINE),
        (AttackVector.NETWORK, Posture.RELAXED, Severity.CRITICAL, Disposition.QUARANTINE),
        (AttackVector.NETWORK, Posture.STRICT, Severity.MEDIUM, Disposition.QUARANTINE),
        # PARANOID skips the AV filter — quarantines AV:L and AV-unknown
        (AttackVector.LOCAL, Posture.PARANOID, Severity.HIGH, Disposition.QUARANTINE),
        (None, Posture.PARANOID, Severity.HIGH, Disposition.QUARANTINE),
        (AttackVector.LOCAL, Posture.PARANOID, Severity.MEDIUM, Disposition.QUARANTINE),
    ],
)
def test_attack_vector_filter_matrix(
    av: AttackVector | None,
    posture: Posture,
    severity: Severity,
    expected: Disposition,
) -> None:
    finding = _finding(severity=severity, attack_vector=av)
    decision = evaluate_finding(
        finding,
        posture=posture,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == expected


def test_av_local_explanation_mentions_paranoid_opt_in() -> None:
    finding = _finding(severity=Severity.HIGH, attack_vector=AttackVector.LOCAL)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert "AV:L" in decision.explanation
    assert "Local" in decision.explanation
    assert "paranoid" in decision.explanation
    assert "balanced" in decision.explanation


def test_av_unknown_explanation_distinct_from_av_l() -> None:
    finding = _finding(severity=Severity.HIGH, attack_vector=None)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert "unspecified" in decision.explanation
    assert "paranoid" in decision.explanation


def test_av_filter_applies_before_hardening_penalty_elevation() -> None:
    """AV:L finding with read_only=False should still go to informational —
    the AV filter trumps elevation, since the elevation reflects local
    container weakness rather than network reachability."""
    finding = _finding(severity=Severity.MEDIUM, attack_vector=AttackVector.LOCAL)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=2,  # would elevate Medium → Critical
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.INFORMATIONAL
    assert decision.effective_severity == Severity.CRITICAL  # still recorded


def test_av_n_with_hardening_penalty_still_quarantines() -> None:
    """AV:N findings still get the elevation behavior."""
    finding = _finding(severity=Severity.MEDIUM, attack_vector=AttackVector.NETWORK)
    decision = evaluate_finding(
        finding,
        posture=Posture.BALANCED,
        hardening_penalty=1,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.QUARANTINE
    assert decision.effective_severity == Severity.HIGH


def test_paranoid_threshold_matches_strict() -> None:
    assert _POSTURE_THRESHOLDS[Posture.PARANOID] == Severity.MEDIUM


def test_paranoid_explanation_mentions_paranoid_label() -> None:
    finding = _finding(severity=Severity.HIGH, attack_vector=AttackVector.NETWORK)
    decision = evaluate_finding(
        finding,
        posture=Posture.PARANOID,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.QUARANTINE
    assert "paranoid" in decision.explanation


def test_paranoid_below_threshold_still_informational() -> None:
    """Paranoid skips the AV filter but the threshold still applies — Low
    is below the Medium threshold so it stays informational."""
    finding = _finding(severity=Severity.LOW, attack_vector=AttackVector.LOCAL)
    decision = evaluate_finding(
        finding,
        posture=Posture.PARANOID,
        hardening_penalty=0,
        dangerously_disable_quarantine=False,
        suppressions=(),
        today=_TODAY,
    )
    assert decision.disposition == Disposition.INFORMATIONAL


# ---------- parse_posture ----------


def test_parse_posture_none_is_balanced() -> None:
    assert parse_posture(None) == Posture.BALANCED


def test_parse_posture_lowercase_balanced() -> None:
    assert parse_posture("balanced") == Posture.BALANCED


def test_parse_posture_uppercase_strict() -> None:
    assert parse_posture("STRICT") == Posture.STRICT


def test_parse_posture_mixed_case_relaxed() -> None:
    assert parse_posture("Relaxed") == Posture.RELAXED


def test_parse_posture_paranoid_accepted() -> None:
    assert parse_posture("paranoid") == Posture.PARANOID
    assert parse_posture("PARANOID") == Posture.PARANOID
    assert parse_posture("Paranoid") == Posture.PARANOID


def test_parse_posture_unknown_raises() -> None:
    with pytest.raises(PolicyError):
        parse_posture("unknown")


def test_parse_posture_empty_string_raises() -> None:
    with pytest.raises(PolicyError):
        parse_posture("")


# ---------- hardening_profile_from_compose ----------


def test_hardening_profile_from_compose_empty_services_is_baseline() -> None:
    """No services in compose → conservative baseline (read_only/no_new_privileges
    can't be confirmed, so they're False; nothing weakened)."""
    profile = hardening_profile_from_compose({"services": {}})
    # With zero services, the AND-fold over an empty set is vacuously True.
    assert profile.read_only is True
    assert profile.no_new_privileges is True
    assert profile.extra_caps_added is False
    assert profile.privileged is False


def test_hardening_profile_single_service_fully_hardened() -> None:
    compose = {
        "services": {
            "web": {
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
            },
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.read_only is True
    assert profile.no_new_privileges is True
    assert profile.extra_caps_added is False
    assert profile.privileged is False


def test_hardening_profile_single_service_read_only_false() -> None:
    compose = {
        "services": {
            "web": {
                "read_only": False,
                "security_opt": ["no-new-privileges:true"],
            },
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.read_only is False
    assert profile.no_new_privileges is True


def test_hardening_profile_single_service_no_read_only_field() -> None:
    """If `read_only` is not set explicitly, treat as not-read-only (False)."""
    compose = {
        "services": {
            "web": {
                "security_opt": ["no-new-privileges:true"],
            },
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.read_only is False


def test_hardening_profile_no_new_privileges_false_explicit() -> None:
    """When the service is NOT in services_with_overlay (i.e. profile: off),
    a literal `no-new-privileges:false` in compose flips the field. With
    overlay applied — the v0.6.2 default — compose_validate would reject
    that combination upstream, so the function trusts the overlay."""
    compose = {
        "services": {
            "web": {
                "read_only": True,
                "security_opt": ["no-new-privileges:false"],
            },
        },
    }
    profile = hardening_profile_from_compose(
        compose, services_with_overlay=set(),
    )
    assert profile.no_new_privileges is False


def test_hardening_profile_no_new_privileges_overlay_enforces_default() -> None:
    """v0.6.2: a service with overlay applied (profile: default) is treated
    as having no-new-privileges enforced, even if user compose doesn't
    redeclare it. Avoids false-positive penalty for projects that simply
    rely on boxmunge's silent floor."""
    compose = {
        "services": {
            "web": {
                "read_only": True,
                # No security_opt declaration
            },
        },
    }
    profile = hardening_profile_from_compose(
        compose, services_with_overlay={"web"},
    )
    assert profile.no_new_privileges is True


def test_hardening_profile_overlay_default_applies_to_all_services() -> None:
    """services_with_overlay=None (default) means "every service has overlay"
    — backward-compatible with callers that haven't been updated."""
    compose = {
        "services": {
            "web": {"read_only": True},
            "worker": {"read_only": True},
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.no_new_privileges is True


def test_hardening_profile_overlay_partial_off_service_still_weakens() -> None:
    """If one service has profile: off (and no explicit no-new-privileges),
    the project's no_new_privileges drops to False — single weakened service
    dominates."""
    compose = {
        "services": {
            "web": {"read_only": True},
            "off_svc": {"read_only": True},
        },
    }
    profile = hardening_profile_from_compose(
        compose, services_with_overlay={"web"},
    )
    # off_svc isn't in overlay set; lacks explicit no-new-privileges → weakens.
    assert profile.no_new_privileges is False


def test_hardening_profile_cap_add_marks_extra_caps() -> None:
    compose = {
        "services": {
            "web": {
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
                "cap_add": ["NET_ADMIN"],
            },
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.extra_caps_added is True


def test_hardening_profile_privileged_true() -> None:
    compose = {
        "services": {
            "web": {
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
                "privileged": True,
            },
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.privileged is True


def test_hardening_profile_multi_service_one_weak_dominates() -> None:
    """One read_only=False service weakens the whole project."""
    compose = {
        "services": {
            "web": {
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
            },
            "worker": {
                "read_only": False,
                "security_opt": ["no-new-privileges:true"],
            },
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.read_only is False
    assert profile.no_new_privileges is True
    assert profile.extra_caps_added is False


def test_hardening_profile_multi_service_extra_caps_or_fold() -> None:
    """Any single service with cap_add → project marked as extra_caps_added."""
    compose = {
        "services": {
            "web": {
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
            },
            "worker": {
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
                "cap_add": ["NET_ADMIN"],
            },
        },
    }
    profile = hardening_profile_from_compose(compose)
    assert profile.extra_caps_added is True


def test_hardening_profile_no_new_privileges_false_takes_precedence() -> None:
    """If a profile: off service has 'no-new-privileges:false' in
    security_opt alongside :true, the project's no_new_privileges is False.
    With overlay applied, compose_validate rejects this combination upstream,
    so we exercise the off-profile path here."""
    compose = {
        "services": {
            "web": {
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
            },
            "worker": {
                "read_only": True,
                "security_opt": [
                    "no-new-privileges:true",
                    "no-new-privileges:false",
                ],
            },
        },
    }
    # Both services treated as profile: off (overlay set is empty).
    profile = hardening_profile_from_compose(
        compose, services_with_overlay=set(),
    )
    assert profile.no_new_privileges is False
