# SPDX-License-Identifier: Apache-2.0
"""Tests for standalone alert-body formatter functions in _alerting_formatters.

The format_* functions are pure (no I/O), so tests here just verify the
contracts: priority level, required keywords in title/body, no exceptions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boxmunge.cve.policy import Disposition, FindingDisposition
    from boxmunge.cve.scanner import Finding, Severity


def _kev(fetched_at=None, released_at=None, source=None):
    from boxmunge.cve.kev import KevCatalog
    return KevCatalog(frozenset(), fetched_at, released_at, source)


def test_kev_stale_alert_is_priority_one_and_names_the_feed() -> None:
    """The alert is priority 1 and its title names the KEV feed."""
    from boxmunge.cve._alerting_fleet import format_kev_stale_alert

    alert = format_kev_stale_alert(_kev(), stale_reason="no catalog", tried=())
    assert alert.priority == 1
    assert "KEV" in alert.title
    assert alert.kind == "kev_stale"


def test_kev_stale_alert_names_the_reason_release_and_source() -> None:
    from boxmunge.cve._alerting_fleet import format_kev_stale_alert

    fetched = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
    released = datetime(2026, 6, 9, 19, 44, 0, tzinfo=timezone.utc)
    alert = format_kev_stale_alert(
        _kev(fetched, released, "https://mirror.example/kev.json"),
        stale_reason="the catalog is lagging", tried=("https://a.example: HTTP 403 Forbidden",))
    assert "stale" in alert.title
    assert "Why: the catalog is lagging." in alert.body
    assert f"released {released.isoformat()}" in alert.body
    assert f"last fetched {fetched.isoformat()}" in alert.body
    assert "from https://mirror.example/kev.json" in alert.body
    assert "- https://a.example: HTTP 403 Forbidden" in alert.body


def test_kev_stale_alert_body_mentions_never_fetched_when_none() -> None:
    from boxmunge.cve._alerting_fleet import format_kev_stale_alert

    body = format_kev_stale_alert(_kev(), stale_reason="x", tried=()).body
    assert "never fetched" in body and "released unknown" in body


def test_kev_alert_on_a_fresh_cache_says_the_refresh_was_rejected() -> None:
    from boxmunge.cve._alerting_fleet import format_kev_stale_alert

    now = datetime.now(timezone.utc)
    alert = format_kev_stale_alert(_kev(now, now, "s"), stale_reason=None,
                                   tried=("s: rejected: feed returned 0 entries",))
    assert "refresh rejected" in alert.title
    assert "Why:" not in alert.body


def test_kev_stale_alert_says_kev_only_postures_cannot_quarantine() -> None:
    from boxmunge.cve._alerting_fleet import format_kev_stale_alert

    body = format_kev_stale_alert(_kev(), stale_reason="x", tried=()).body
    assert "relaxed and balanced (the default) KEV is the only quarantine trigger" in body
    assert "nothing can quarantine those projects" in body


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


# ---------- format_new_findings_alert ----------


def test_informational_alert_includes_distro_reason() -> None:
    """Body must surface finding.explanation, replacing the old hard-coded
    'Below quarantine threshold' line, so the operator sees the real reason
    (e.g. distro-deprioritized) instead of an always-wrong boilerplate."""
    from boxmunge.cve._alerting_formatters import format_new_findings_alert
    from boxmunge.cve._alerting_types import Hit
    from boxmunge.cve.policy import Disposition
    from boxmunge.cve.policy_explain import explain_distro_deprioritized
    from boxmunge.cve.scanner import Severity, VulnStatus

    distro_expl = explain_distro_deprioritized(VulnStatus.WILL_NOT_FIX, Severity.LOW)
    fd = _make_fd(
        disposition=Disposition.INFORMATIONAL,
        explanation=distro_expl,
    )
    alert = format_new_findings_alert("demo", [Hit(fd, "myapp:1.0")])
    assert distro_expl in alert.body
    assert "Below quarantine threshold" not in alert.body


# ---------- format_quarantine_alert ----------


def test_quarantine_alert_includes_explanation() -> None:
    """Body must include finding.explanation so the operator sees WHY the
    project was quarantined (threshold, KEV, etc.)."""
    from boxmunge.cve._alerting_formatters import format_quarantine_alert
    from boxmunge.cve._alerting_types import Hit
    from boxmunge.cve.policy import Disposition
    from boxmunge.cve.policy_explain import explain_kev_quarantine

    kev_expl = explain_kev_quarantine("CVE-2026-9999")
    fd = _make_fd(
        cve_id="CVE-2026-9999",
        disposition=Disposition.QUARANTINE,
        explanation=kev_expl,
    )
    alert = format_quarantine_alert("demo", [Hit(fd, "myapp:1.0")])
    assert "Known Exploited" in alert.body
    assert kev_expl in alert.body


def test_quarantine_alert_kev_unknown_severity_reads_sensibly() -> None:
    """A KEV-override quarantine with UNKNOWN severity still produces a
    readable alert body because the KEV explanation (naming 'Known Exploited
    Vulnerabilities') provides the real justification.  The (Unknown) severity
    tag in the title is not confusing when the body names KEV."""
    from boxmunge.cve._alerting_formatters import format_quarantine_alert
    from boxmunge.cve._alerting_types import Hit
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
    alert = format_quarantine_alert("demo", [Hit(fd, "myapp:1.0")])
    # Title carries (Unknown) — that's OK
    assert "Unknown" in alert.title
    # Body must name KEV so the operator understands the quarantine rationale
    assert "Known Exploited" in alert.body
    # Standard quarantine action guidance must still be present
    assert "Service stopped" in alert.body
    assert "boxmunge security resume" in alert.body
