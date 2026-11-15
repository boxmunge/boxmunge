# SPDX-License-Identifier: Apache-2.0
"""Strict's fix grace: an at-gate fix not deployed within 7 days quarantines,
with one warning 48 hours before (cve.fix_grace)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.cve.exploited import ExploitedSource
from boxmunge.cve.fix_grace import (
    STRICT_FIX_GRACE,
    STRICT_FIX_WARN_BEFORE,
    FixGrace,
    apply_fix_grace,
)
from boxmunge.cve.policy import Disposition, FindingDisposition, Posture, ProjectDecision
from boxmunge.cve.scanner import Finding, Severity
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

P = "shop"
T0 = datetime(2026, 11, 1, 3, 0, tzinfo=timezone.utc)


def _fixable(cve: str = "CVE-2026-0001", package: str = "openssl") -> FindingDisposition:
    return FindingDisposition(
        finding=Finding(cve_id=cve, severity=Severity.MEDIUM, package=package,
                        installed_version="3.0.1", fixed_version="3.0.2",
                        title="t", primary_url=None),
        base_severity=Severity.MEDIUM, hardening_penalty=0,
        effective_severity=Severity.MEDIUM, disposition=Disposition.IGNORED_FIXED,
        suppression=None, explanation="fix available", fix_would_quarantine=True,
        fix_meets_patch_gate=True,
    )


def _decision(*findings: FindingDisposition, at: datetime = T0) -> ProjectDecision:
    return ProjectDecision(
        project_name=P, image_ref="shop:1", findings=tuple(findings),
        quarantine_required=False, at_risk_running=False, scanned_at=at,
    )


def _run(paths: BoxPaths, now: datetime, *findings: FindingDisposition,
         posture: Posture = Posture.STRICT, dangerously: bool = False, complete: bool = True):
    grace = FixGrace.load(paths, P)
    out, alerts = apply_fix_grace([_decision(*findings, at=now)], grace, now, posture,
                                  dangerously=dangerously, complete=complete)
    grace.save()
    return out, alerts


def _disp(decisions: list[ProjectDecision]) -> Disposition:
    return decisions[0].findings[0].disposition


def test_grace_values() -> None:
    assert STRICT_FIX_GRACE == timedelta(days=7)
    assert STRICT_FIX_WARN_BEFORE == timedelta(hours=48)


def test_first_seen_recorded_once(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable())
    _run(paths, T0 + timedelta(days=1), _fixable())
    assert FixGrace.load(paths, P).first_seen(("CVE-2026-0001", "openssl")) == T0


def test_warning_sent_once_at_48h(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable())
    before = T0 + STRICT_FIX_GRACE - STRICT_FIX_WARN_BEFORE - timedelta(minutes=1)
    assert _run(paths, before, _fixable())[1] == []
    at = T0 + STRICT_FIX_GRACE - STRICT_FIX_WARN_BEFORE
    out, alerts = _run(paths, at, _fixable())
    assert [a.kind for a in alerts] == ["fix_deadline"]
    assert alerts[0].priority == 0
    assert "2026-11-08" in alerts[0].body and "3.0.2" in alerts[0].body
    assert "CVE-2026-0001" in alerts[0].title
    assert _disp(out) is Disposition.IGNORED_FIXED
    # Idempotent across many scans a day: no second warning.
    assert _run(paths, at + timedelta(hours=1), _fixable())[1] == []


def test_quarantine_after_7_days(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable())
    out, _ = _run(paths, T0 + STRICT_FIX_GRACE - timedelta(seconds=1), _fixable())
    assert _disp(out) is Disposition.IGNORED_FIXED
    out, _ = _run(paths, T0 + STRICT_FIX_GRACE, _fixable())
    fd = out[0].findings[0]
    assert fd.disposition is Disposition.QUARANTINE
    assert out[0].quarantine_required
    assert "available since 2026-11-01 but not deployed" in fd.explanation.lower()
    assert not fd.fix_would_quarantine
    # Still recognisably fixable, for autofix.
    assert fd.finding.fix_available and fd.finding.fixed_version == "3.0.2"
    assert fd.fix_meets_patch_gate


def test_quarantine_disabled_runs_at_risk(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable(), dangerously=True)
    out, _ = _run(paths, T0 + STRICT_FIX_GRACE, _fixable(), dangerously=True)
    assert _disp(out) is Disposition.STILL_RUNNING_AT_RISK
    assert out[0].at_risk_running and not out[0].quarantine_required


def test_resolved_finding_pruned(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable())
    _run(paths, T0 + timedelta(days=1))                 # fix deployed: finding gone
    assert FixGrace.load(paths, P).first_seen(("CVE-2026-0001", "openssl")) is None
    later = T0 + timedelta(days=8)
    out, _ = _run(paths, later, _fixable())             # reappears: a new grace
    assert _disp(out) is Disposition.IGNORED_FIXED
    assert FixGrace.load(paths, P).first_seen(("CVE-2026-0001", "openssl")) == later


def test_incomplete_scan_keeps_unseen_entries(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable())
    _run(paths, T0 + timedelta(days=1), complete=False)
    assert FixGrace.load(paths, P).first_seen(("CVE-2026-0001", "openssl")) == T0


@pytest.mark.parametrize("posture", [Posture.RELAXED, Posture.BALANCED, Posture.PARANOID])
def test_grace_only_under_strict(paths: BoxPaths, posture: Posture) -> None:
    _run(paths, T0, _fixable(), posture=posture)
    out, alerts = _run(paths, T0 + timedelta(days=30), _fixable(), posture=posture)
    assert _disp(out) is Disposition.IGNORED_FIXED and alerts == []
    assert FixGrace.load(paths, P).first_seen(("CVE-2026-0001", "openssl")) is None


def test_posture_change_prunes(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable())
    _run(paths, T0 + timedelta(days=1), _fixable(), posture=Posture.BALANCED)
    assert FixGrace.load(paths, P).first_seen(("CVE-2026-0001", "openssl")) is None


def test_below_gate_and_full_kev_are_not_graced(paths: BoxPaths) -> None:
    below = replace(_fixable("CVE-2026-0002"), fix_would_quarantine=False)
    kev = replace(_fixable("CVE-2026-0003"), exploited_by=frozenset({ExploitedSource.CISA}))
    _run(paths, T0, below, kev)
    grace = FixGrace.load(paths, P)
    assert grace.first_seen(("CVE-2026-0002", "openssl")) is None
    assert grace.first_seen(("CVE-2026-0003", "openssl")) is None


def test_unreadable_grace_state_raises_state_error(paths: BoxPaths) -> None:
    path = paths.project_fix_grace(P)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json")
    with pytest.raises(StateError, match=str(path)):
        FixGrace.load(paths, P)
    path.write_text('{"entries": [{"cve_id": "CVE-1"}]}')
    with pytest.raises(StateError, match=str(path)):
        FixGrace.load(paths, P)


def test_nothing_written_when_nothing_graced(paths: BoxPaths) -> None:
    _run(paths, T0)
    assert not paths.project_fix_grace(P).exists()


def test_fix_deadline_is_sent_on_its_own_not_digested() -> None:
    from boxmunge.cve._alerting_digest import LOW_URGENCY_KINDS
    assert "fix_deadline" not in LOW_URGENCY_KINDS


def test_overdue_quarantine_alert_title_says_the_fix_is_not_deployed(paths: BoxPaths) -> None:
    from boxmunge.cve.alerting import Hit, format_quarantine_alert
    _run(paths, T0, _fixable())
    out, _ = _run(paths, T0 + STRICT_FIX_GRACE, _fixable())
    alert = format_quarantine_alert(P, [Hit(out[0].findings[0], "shop:1")])
    assert "QUARANTINED — CVE-2026-0001 (Medium, fix not deployed)" in alert.title
    assert "but not deployed" in alert.body


def _write_entry(paths: BoxPaths, first_seen: str, warned_at: str | None) -> None:
    import json
    path = paths.project_fix_grace(P)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"entries": [{"cve_id": "CVE-2026-0001", "package": "openssl",
                                             "first_seen": first_seen, "warned_at": warned_at}]}))


def test_future_first_seen_is_refused_not_a_postponed_deadline(paths: BoxPaths) -> None:
    _write_entry(paths, "9999-01-01T00:00:00+00:00", None)
    path = paths.project_fix_grace(P)
    with pytest.raises(StateError, match=str(path)) as e:
        _run(paths, T0, _fixable())
    assert f"remove {path} to restart that project's fix deadlines" in str(e.value)


def test_first_seen_within_clock_skew_is_accepted(paths: BoxPaths) -> None:
    _write_entry(paths, (T0 + timedelta(seconds=30)).isoformat(), None)
    out, _ = _run(paths, T0, _fixable())
    assert _disp(out) is Disposition.IGNORED_FIXED


def test_warned_before_first_seen_is_refused(paths: BoxPaths) -> None:
    _write_entry(paths, T0.isoformat(), (T0 - timedelta(days=1)).isoformat())
    path = paths.project_fix_grace(P)
    with pytest.raises(StateError, match=str(path)) as e:
        FixGrace.load(paths, P)
    assert f"remove {path} to restart that project's fix deadlines" in str(e.value)


def test_warning_under_quarantine_disabled_says_it_runs_at_risk(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable(), dangerously=True)
    _, [alert] = _run(paths, T0 + timedelta(days=6), _fixable(), dangerously=True)
    assert "quarantined" not in alert.title + alert.body
    assert "runs at risk" in alert.title and "runs at risk" in alert.body


def test_warning_says_the_site_is_quarantined(paths: BoxPaths) -> None:
    _run(paths, T0, _fixable())
    _, [alert] = _run(paths, T0 + timedelta(days=6), _fixable())
    assert "or the site is quarantined" in alert.title and "or the site is quarantined" in alert.body


def test_first_write_leaves_the_directory_deploy_owned(paths: BoxPaths) -> None:
    """Root writing first must not leave state/cve/fix_grace root-owned."""
    from unittest.mock import patch
    chowned: list[str] = []
    with patch("boxmunge.fs_nofollow._chown_deploy", side_effect=chowned.append):
        _run(paths, T0, _fixable())
    assert str(paths.project_fix_grace(P).parent) in chowned
