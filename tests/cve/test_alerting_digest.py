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
