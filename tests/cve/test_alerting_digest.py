# SPDX-License-Identifier: Apache-2.0
"""The fleet scan digest and the posture filter on informational alerts."""

from __future__ import annotations

import pytest

from boxmunge.cve.alerting import (
    Alert, Hit, detect_transitions, format_awaiting_fix_alert,
    format_new_findings_alert, format_quarantine_alert, format_scan_digest,
    is_low_urgency,
)
from boxmunge.cve.policy import Disposition, Posture
from boxmunge.cve.scanner import Severity
from tests.cve.test_alerting import _decision, _disp


def _transitions(posture, *fds):
    return detect_transitions(
        project_name="demo", posture=posture, current=(_decision(*fds),),
        prior=(), suppressions=(),
    )


_INFO = dict(disposition=Disposition.INFORMATIONAL, base=Severity.MEDIUM)


@pytest.mark.parametrize("posture", [Posture.RELAXED, Posture.BALANCED])
def test_informational_dropped_at_balanced_and_looser(posture) -> None:
    t = _transitions(posture, _disp(**_INFO))
    assert t.alerts == ()
    assert [a.kind for a in t.dropped] == ["informational"]


@pytest.mark.parametrize("posture", [Posture.STRICT, Posture.PARANOID])
def test_informational_kept_at_stricter_postures(posture) -> None:
    t = _transitions(posture, _disp(**_INFO))
    assert [a.kind for a in t.alerts] == ["informational"]
    assert t.dropped == ()


def test_awaiting_fix_kept_at_balanced() -> None:
    t = _transitions(Posture.BALANCED,
                     _disp(disposition=Disposition.AWAITING_FIX, base=Severity.HIGH))
    assert [a.kind for a in t.alerts] == ["awaiting_fix"]


def test_urgent_kinds_are_not_low_urgency() -> None:
    hit = Hit(_disp(), "myapp:1.0")
    assert not is_low_urgency(format_quarantine_alert("demo", [hit]))
    assert is_low_urgency(format_awaiting_fix_alert("demo", [hit]))


def _low(project: str, *severities: Severity) -> Alert:
    hits = [Hit(_disp(f"CVE-2026-{i}", base=s, **{"disposition": Disposition.INFORMATIONAL}),
                "myapp:1.0") for i, s in enumerate(severities)]
    return format_new_findings_alert(project, hits)


def test_digest_is_one_quiet_line_per_project() -> None:
    digest = format_scan_digest([
        _low("blog", Severity.LOW, Severity.HIGH),
        _low("shop", Severity.MEDIUM),
        format_awaiting_fix_alert("blog", [Hit(_disp(base=Severity.CRITICAL), "i")]),
    ])
    assert digest.kind == "scan_digest"
    assert digest.priority == -1
    lines = digest.body.splitlines()
    assert lines[0] == "blog: 3 new, highest Critical"
    assert lines[1] == "shop: 1 new, highest Medium"
    assert "2 projects" in digest.title


def test_digest_refuses_urgent_alerts() -> None:
    hit = Hit(_disp(), "myapp:1.0")
    with pytest.raises(ValueError):
        format_scan_digest([format_quarantine_alert("demo", [hit])])
    with pytest.raises(ValueError):
        format_scan_digest([])


# ---------- the nightly autofix digest ----------


def _patched(project: str, n: int = 1) -> Alert:
    from datetime import datetime, timezone

    from boxmunge.cve.alerting import format_nightly_patched_line
    from boxmunge.cve.autofix_record import PackageChange, PatchRecord
    record = PatchRecord(
        project=project, service="web", base_ref="web:1", base_digest="sha256:" + "b" * 64,
        patched_ref=f"boxmunge.invalid/{project}/web:autofix-" + "a" * 12, patched_image_id="sha256:" + "a" * 64,
        packages=tuple(PackageChange(f"p{i}", "1", "2") for i in range(n)),
        cves=("CVE-2026-0001",), created_at=datetime.now(timezone.utc), trigger="nightly")
    return format_nightly_patched_line(project, ("CVE-2026-0001",), (record,))


def test_autofix_digest_lists_patched_then_failed() -> None:
    from boxmunge.cve.alerting import format_autofix_digest, format_nightly_failed_line
    digest = format_autofix_digest([
        format_nightly_failed_line("blog", step="build", reason="apt-get exited 100"),
        _patched("shop", 2), _patched("api"),
    ])
    assert digest.priority == -1 and digest.kind == "autofix_digest"
    assert digest.title == "Nightly autofix: 2 projects patched, 1 could not be patched"
    assert digest.body.splitlines()[:3] == [
        "patched: api: CVE-2026-0001 (1 package)",
        "patched: shop: CVE-2026-0001 (2 packages)",
        "could not patch: blog: build: apt-get exited 100",
    ]


def test_autofix_digest_of_failures_only() -> None:
    from boxmunge.cve.alerting import format_autofix_digest, format_nightly_failed_line
    digest = format_autofix_digest([
        format_nightly_failed_line("blog", step=None, reason="RuntimeError: boom"),
        format_nightly_failed_line("shop", step="scan", reason="x")])
    assert digest.title == "Nightly autofix: 2 projects could not be patched"
    assert "could not patch: blog: unexpected error: RuntimeError: boom" in digest.body


def test_autofix_digest_refuses_urgent_and_scan_alerts() -> None:
    from boxmunge.cve.alerting import format_autofix_digest, format_autofix_failed_alert
    loud = format_autofix_failed_alert("demo", ("CVE-2026-0001",), step="health",
                                       reason="x", site="y", timing="z")
    with pytest.raises(ValueError):
        format_autofix_digest([loud])
    with pytest.raises(ValueError):
        format_autofix_digest([])
    assert not is_low_urgency(_patched("demo"))   # never in the scan's own digest


def test_autofix_digest_orders_every_group() -> None:
    from boxmunge.cve.alerting import (
        format_autofix_digest, format_nightly_deferred_line, format_nightly_failed_line,
        format_nightly_gone_line, format_nightly_skipped_line,
    )
    digest = format_autofix_digest([
        format_nightly_deferred_line("zed"),
        format_nightly_skipped_line("web", "container update failed: unhealthy: app"),
        format_nightly_failed_line("blog", step="build", reason="x"),
        format_nightly_gone_line("docs", ("CVE-2026-0002",), updated=True),
        format_nightly_gone_line("api", ("CVE-2026-0003",), updated=False),
        _patched("shop"),
    ])
    assert digest.title == ("Nightly autofix: 1 project patched, 2 already fixed, "
                            "1 could not be patched, 1 skipped, 1 deferred")
    assert digest.body.splitlines()[:6] == [
        "patched: shop: CVE-2026-0001 (1 package)",
        "no longer in the running images: api: CVE-2026-0003",
        "fixed by tonight's update: docs: CVE-2026-0002",
        "could not patch: blog: build: x",
        "skipped: web: container update failed: unhealthy: app",
        "deferred to the next maintenance window: zed",
    ]
