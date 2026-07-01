# SPDX-License-Identifier: Apache-2.0
"""Tests for standalone alert-body formatter functions in _alerting_formatters.

The format_* functions are pure (no I/O), so tests here just verify the
contracts: priority level, required keywords in title/body, no exceptions.
"""
from __future__ import annotations

from datetime import datetime, timezone


def test_kev_stale_alert_is_priority_one_and_names_the_feed() -> None:
    """format_kev_stale_alert(None) must return a priority-1 Alert whose
    title references the KEV feed so the operator knows what degraded."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    alert = format_kev_stale_alert(None)
    assert alert.priority == 1
    assert "KEV" in alert.title


def test_kev_stale_alert_with_fetched_at_includes_timestamp() -> None:
    """When fetched_at is provided, the body must include the ISO timestamp
    so operators can see when the feed was last successfully fetched."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    ts = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
    alert = format_kev_stale_alert(ts)
    assert alert.priority == 1
    assert "KEV" in alert.title
    assert ts.isoformat() in alert.body


def test_kev_stale_alert_body_mentions_never_fetched_when_none() -> None:
    """When fetched_at is None, the body should indicate the feed was never
    fetched so the operator knows this is a fresh/unconfigured state."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    alert = format_kev_stale_alert(None)
    assert "never fetched" in alert.body


def test_kev_stale_alert_kind() -> None:
    """The alert kind must be 'kev_stale' for correct routing/filtering."""
    from boxmunge.cve._alerting_formatters import format_kev_stale_alert

    alert = format_kev_stale_alert(None)
    assert alert.kind == "kev_stale"


# ---------- helpers for format_quarantine_alert / format_informational_alert ----------


def _make_finding(
    cve_id: str = "CVE-2026-0001",
    severity: "Severity" = None,
) -> "Finding":
    from boxmunge.cve.scanner import Finding, Severity

    sev = severity if severity is not None else Severity.HIGH
    return Finding(
        cve_id=cve_id,
        severity=sev,
        package="openssl",
        installed_version="1.1.1k",
        fixed_version=None,
        title="Test CVE",
        primary_url=None,
    )


def _make_fd(
    cve_id: str = "CVE-2026-0001",
    base: "Severity" = None,
    effective: "Severity" = None,
    disposition: "Disposition" = None,
    explanation: str = "test explanation",
    penalty: int = 0,
) -> "FindingDisposition":
    from boxmunge.cve.policy import Disposition, FindingDisposition
    from boxmunge.cve.scanner import Severity

    b = base if base is not None else Severity.HIGH
    eff = effective if effective is not None else b
    d = disposition if disposition is not None else Disposition.QUARANTINE
    return FindingDisposition(
        finding=_make_finding(cve_id=cve_id, severity=b),
        base_severity=b,
        hardening_penalty=penalty,
        effective_severity=eff,
        disposition=d,
        suppression=None,
        explanation=explanation,
    )


def _make_decision(fd: "FindingDisposition", project: str = "demo") -> "ProjectDecision":
    from datetime import datetime, timezone

    from boxmunge.cve.policy import Disposition, ProjectDecision

    quarantine = fd.disposition == Disposition.QUARANTINE
    return ProjectDecision(
        project_name=project,
        image_ref="myapp:1.0",
        findings=(fd,),
        quarantine_required=quarantine,
        at_risk_running=False,
        scanned_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )


# ---------- format_informational_alert ----------


def test_informational_alert_includes_distro_reason() -> None:
    """Body must surface finding.explanation, replacing the old hard-coded
    'Below quarantine threshold' line, so the operator sees the real reason
    (e.g. distro-deprioritized) instead of an always-wrong boilerplate."""
    from boxmunge.cve._alerting_formatters import format_informational_alert
    from boxmunge.cve.policy import Disposition
    from boxmunge.cve.policy_explain import explain_distro_deprioritized
    from boxmunge.cve.scanner import Severity, VulnStatus

    distro_expl = explain_distro_deprioritized(VulnStatus.WILL_NOT_FIX, Severity.LOW)
    fd = _make_fd(
        disposition=Disposition.INFORMATIONAL,
        explanation=distro_expl,
    )
    pd = _make_decision(fd)
    alert = format_informational_alert(pd, fd)
    assert distro_expl in alert.body
    assert "Below quarantine threshold" not in alert.body


# ---------- format_quarantine_alert ----------


def test_quarantine_alert_includes_explanation() -> None:
    """Body must include finding.explanation so the operator sees WHY the
    project was quarantined (threshold, KEV, etc.)."""
    from boxmunge.cve._alerting_formatters import format_quarantine_alert
    from boxmunge.cve.policy import Disposition
    from boxmunge.cve.policy_explain import explain_kev_quarantine

    kev_expl = explain_kev_quarantine("CVE-2026-9999")
    fd = _make_fd(
        cve_id="CVE-2026-9999",
        disposition=Disposition.QUARANTINE,
        explanation=kev_expl,
    )
    pd = _make_decision(fd)
    alert = format_quarantine_alert(pd, fd)
    assert "Known Exploited" in alert.body
    assert kev_expl in alert.body


def test_quarantine_alert_kev_unknown_severity_reads_sensibly() -> None:
    """A KEV-override quarantine with UNKNOWN severity still produces a
    readable alert body because the KEV explanation (naming 'Known Exploited
    Vulnerabilities') provides the real justification.  The (Unknown) severity
    tag in the title is not confusing when the body names KEV."""
    from boxmunge.cve._alerting_formatters import format_quarantine_alert
    from boxmunge.cve.policy import Disposition
    from boxmunge.cve.policy_explain import explain_kev_quarantine
    from boxmunge.cve.scanner import Severity

    kev_expl = explain_kev_quarantine("CVE-2026-KUNK")
    fd = _make_fd(
        cve_id="CVE-2026-KUNK",
        base=Severity.UNKNOWN,
        effective=Severity.UNKNOWN,
        disposition=Disposition.QUARANTINE,
        explanation=kev_expl,
    )
    pd = _make_decision(fd)
    alert = format_quarantine_alert(pd, fd)
    # Title carries (Unknown) — that's OK
    assert "Unknown" in alert.title
    # Body must name KEV so the operator understands the quarantine rationale
    assert "Known Exploited" in alert.body
    # Standard quarantine action guidance must still be present
    assert "Service stopped" in alert.body
    assert "boxmunge security resume" in alert.body
