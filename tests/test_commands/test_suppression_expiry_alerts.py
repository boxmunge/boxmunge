# SPDX-License-Identifier: Apache-2.0
"""Suppression expiry warnings and expiry alerts through the real fleet scan,
policy and enforcement (Docker and Trivy stubbed)."""
from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone

import pytest
import yaml

from boxmunge.commands import security_actions, security_scan_core
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.cve.breaker import read_held
from boxmunge.cve.exploited import ExploitedIndex, ExploitedSource
from boxmunge.cve.policy import ProjectDecision
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scan_state import write_scan_state
from boxmunge.cve.scanner import TrivyNotInstalledError
from boxmunge.cve.suppression_record import read_record
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, scan_result, seed_quarantine, write_project,
)

CVE = "CVE-2026-57433"
TODAY = datetime.now(timezone.utc).date()
# Every run judges by this clock: 03:00 UTC today, so TODAY + 2 days is 45h out.
NOW = datetime.combine(TODAY, time(3), tzinfo=timezone.utc)


@pytest.fixture
def box(tmp_path, monkeypatch):
    """shop (paranoid) and blog (balanced) carry CVE; wiki (paranoid) does
    not. Returns (paths, pushover, carriers, docker): ``carriers`` is the set
    of projects whose image carries CVE, which a test may change."""
    paths = make_box(tmp_path, projects=("shop", "wiki"))
    write_project(paths, "blog", security={"posture": "balanced"})
    (paths.state / "projects.txt").write_text("shop\nwiki\nblog\n")
    carriers = {"shop", "blog"}
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(
        security_scan_core, "scan_image",
        lambda ref, timeout: scan_result(
            ref, [finding(CVE)] if ref.split("-")[0] in carriers else []),
    )
    monkeypatch.setattr(security_scan_core, "_now", lambda: NOW)
    monkeypatch.setattr(security_scan_core, "_today", lambda: TODAY)
    docker = Docker(monkeypatch)
    return paths, Pushover(monkeypatch, paths), carriers, docker


def _suppress(paths, until: date, *, project: str | None = None) -> None:
    """Write one suppression for CVE: host scope, or ``project``'s."""
    target = (paths.host_suppressions if project is None
              else paths.projects / project / "security" / "suppressions.yml")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump({"suppressions": [{
        "cve": CVE, "until": until.isoformat(), "reason": "not reachable",
        "reviewed_by": "ops", "added": (TODAY - timedelta(days=30)).isoformat(),
    }]}))


def _sent(pushover, words: str):
    return [s for s in pushover.sent if words in s[0]]


def _scanned_yesterday(paths, *names: str) -> None:
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    for name in names:
        write_scan_state(paths.project_scan_state(name), scanned_at=yesterday, decisions=(
            ProjectDecision(name, f"{name}-web:1", (), False, False, yesterday),))


# ---------- the advance warning ----------


def test_host_warning_names_each_projects_outcome_once(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=2))
    cmd_security_scan([], paths)
    [(title, body, priority)] = _sent(pushover, "host suppression expires")
    assert f"{CVE} host suppression expires in" in title
    assert title.endswith("— 1 project will be quarantined")
    assert priority == 1
    assert "- 1 project will be quarantined (stopped): shop [paranoid]" in body
    assert "- 1 project will alert only and keep running: blog [balanced]" in body
    assert "- 1 project has no finding for it (no effect)" in body
    assert f"boxmunge security suppress {CVE} --host --until <date>" in body
    assert not any(is_quarantined(p, paths) for p in ("shop", "blog", "wiki"))
    pushover.clear()
    cmd_security_scan([], paths)
    assert _sent(pushover, "expires") == []


def test_no_warning_before_the_window(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=3))
    cmd_security_scan([], paths)
    assert _sent(pushover, "expires") == []
    assert read_record(paths).warned == {}


def test_single_project_scan_leaves_the_host_warning_to_the_fleet_run(box):
    """It judges one project; the host warning needs the whole fleet."""
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=1))
    cmd_security_scan(["shop"], paths)
    assert _sent(pushover, "expires") == []
    cmd_security_scan([], paths)
    assert len(_sent(pushover, "host suppression expires")) == 1


def test_host_warning_with_no_carrier_is_normal_priority(box):
    paths, pushover, carriers, _ = box
    carriers.clear()
    _suppress(paths, TODAY + timedelta(days=2))
    cmd_security_scan([], paths)
    [(title, body, priority)] = _sent(pushover, "host suppression expires")
    assert title.endswith("— no project affected") and priority == 0
    assert "- 3 projects have no finding for it (no effect)" in body


def test_project_warning_once_and_again_for_an_extension(box):
    """Once per (CVE, scope, project, until): extended, the new date is a new
    window, warned again when it nears."""
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=1), project="shop")
    cmd_security_scan([], paths)
    [(title, body, priority)] = _sent(pushover, "project suppression expires")
    assert f"[boxmunge:shop] {CVE} project suppression expires in " in title
    assert title.endswith("— will be quarantined")
    assert priority == 1
    assert "- shop [paranoid] will be quarantined (stopped)" in body
    assert f"boxmunge security suppress {CVE} --project shop" in body
    pushover.clear()
    cmd_security_scan(["shop"], paths)
    assert _sent(pushover, "expires") == []
    _suppress(paths, TODAY + timedelta(days=2), project="shop")   # extended
    cmd_security_scan(["shop"], paths)
    assert len(_sent(pushover, "project suppression expires")) == 1
    assert {k[3] for k in read_record(paths).warned} == {
        (TODAY + timedelta(days=1)).isoformat(), (TODAY + timedelta(days=2)).isoformat()}


def test_extended_after_the_warning_never_expires(box):
    """The scan dates straddle the old until; the suppression now runs later."""
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=30), project="shop")
    _scanned_yesterday(paths, "shop", "wiki", "blog")
    cmd_security_scan([], paths)
    assert _sent(pushover, "expired") == []


def _corrupt_record(paths) -> None:
    paths.suppression_notices.parent.mkdir(parents=True, exist_ok=True)
    paths.suppression_notices.write_text("{not json")


def test_unusable_record_sends_its_own_alert_from_the_fleet_run(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=2))
    _corrupt_record(paths)
    assert cmd_security_scan([], paths) == 1
    assert _sent(pushover, "expires") == []
    assert _sent(pushover, "CVE scan incomplete") == []
    [(title, body, priority)] = _sent(pushover, "Suppression expiry warnings stopped")
    assert priority == 1
    assert str(paths.suppression_notices) in body and f"remove {paths.suppression_notices}" in body


def test_unusable_record_is_not_alerted_by_a_partial_run(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=1), project="shop")
    _corrupt_record(paths)
    assert cmd_security_scan(["shop"], paths) == 1
    assert _sent(pushover, "Suppression expiry warnings stopped") == []
    assert _sent(pushover, "expires") == []


def test_undelivered_warning_is_sent_again_next_scan(box, monkeypatch):
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=2))
    monkeypatch.setattr("boxmunge.notify.send_notification", lambda *a, **k: False)
    cmd_security_scan([], paths)
    assert read_record(paths).warned == {}
    monkeypatch.setattr("boxmunge.notify.send_notification", pushover._send)
    cmd_security_scan([], paths)
    assert len(_sent(pushover, "host suppression expires")) == 1
    pushover.clear()
    cmd_security_scan([], paths)
    assert _sent(pushover, "expires") == []


def test_one_clock_per_run_across_midnight(box, monkeypatch):
    """A run that crosses 00:00 UTC judges every project by its start: here
    the start is just outside the window, so no project is warned, rather
    than the later ones alone in a partial warning that is never corrected."""
    paths, pushover, *_ = box
    until = TODAY + timedelta(days=3)
    start = datetime.combine(until, time(), tzinfo=timezone.utc) - timedelta(hours=53)
    ticks = iter([start + timedelta(hours=h) for h in range(10)])
    monkeypatch.setattr(security_scan_core, "_now", lambda: next(ticks))
    monkeypatch.setattr(security_scan_core, "_today", lambda: start.date())
    _suppress(paths, until)
    cmd_security_scan([], paths)
    assert _sent(pushover, "expires") == []
    assert read_record(paths).warned == {}


# ---------- the expiry alert ----------


def test_host_expiry_says_what_happened_once_per_run(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY)
    _scanned_yesterday(paths, "shop", "wiki", "blog")
    cmd_security_scan([], paths)
    assert is_quarantined("shop", paths)
    [(title, body, priority)] = _sent(pushover, "host suppression expired")
    assert title.endswith(f"{CVE} host suppression expired — 1 project quarantined")
    assert priority == 1
    assert "- 1 project is quarantined (stopped): shop [paranoid]" in body
    assert "- 1 project alerts only and keeps running: blog [balanced]" in body
    assert "- 1 project has no finding for it (no effect)" in body
    assert _sent(pushover, "project suppression expired") == []


def test_expiry_held_by_the_breaker(box):
    """Two paranoid carriers of three projects trip the breaker."""
    paths, pushover, carriers, _ = box
    carriers.add("wiki")
    _suppress(paths, TODAY)
    _scanned_yesterday(paths, "shop", "wiki", "blog")
    cmd_security_scan([], paths)
    assert set(read_held(paths)) == {"shop", "wiki"}
    [(title, body, priority)] = _sent(pushover, "host suppression expired")
    assert title.endswith("— 2 projects quarantine held by the breaker") and priority == 1
    assert ("- 2 projects are held by the circuit breaker, still running: "
            "shop [paranoid], wiki [paranoid]") in body


def test_project_expiry_with_no_finding_is_normal_priority(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY, project="wiki")
    _scanned_yesterday(paths, "wiki")
    cmd_security_scan(["wiki"], paths)
    [(title, body, priority)] = _sent(pushover, "project suppression expired")
    assert "[boxmunge:wiki]" in title and title.endswith("— no effect")
    assert priority == 0
    assert "no finding for it in the project's images" in body


def test_vulncheck_listing_is_judged_per_posture(box, monkeypatch):
    """A VulnCheck-only listing: paranoid already ignores the suppression, so
    its expiry changes nothing there; under balanced the suppression applies,
    and its expiry only alerts (the site stays up)."""
    paths, pushover, *_ = box
    monkeypatch.setattr(security_scan_core, "load_exploited", lambda p, today, cisa=None:
                        ExploitedIndex({CVE: frozenset({ExploitedSource.VULNCHECK})}, {}))
    _suppress(paths, TODAY + timedelta(days=2))
    cmd_security_scan([], paths)
    [(_, body, _)] = _sent(pushover, "host suppression expires")
    assert "will alert only and keep running: blog [balanced; known exploited (VulnCheck" in body
    assert ("already ignores it (a known-exploited listing overrides it): shop [paranoid; "
            "known exploited (VulnCheck") in body
    assert "will be quarantined" not in body


def test_project_suppression_outliving_the_host_one_keeps_it_covered(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY + timedelta(days=1))
    _suppress(paths, TODAY + timedelta(days=20), project="shop")
    cmd_security_scan([], paths)
    [(title, body, _)] = _sent(pushover, "host suppression expires")
    assert "- 1 project stays covered by another suppression: shop [paranoid]" in body
    assert title.endswith("— 1 project will alert only")


def test_partial_run_leaves_the_host_expiry_to_the_fleet_run(box):
    """A single-project scan on the expiry day judges one project: the host
    expiry waits for the fleet run, which judges every project."""
    paths, pushover, *_ = box
    _suppress(paths, TODAY)
    _scanned_yesterday(paths, "shop", "wiki", "blog")
    cmd_security_scan(["blog"], paths)
    assert _sent(pushover, "host suppression expired") == []
    assert set(read_record(paths).pending) == {(CVE, TODAY.isoformat())}
    cmd_security_scan([], paths)
    [(title, body, priority)] = _sent(pushover, "host suppression expired")
    assert title.endswith("— 1 project quarantined") and priority == 1
    assert "- 1 project alerts only and keeps running: blog [balanced]" in body
    assert read_record(paths).pending == {}


def test_expiry_survives_an_enforcement_error_after_recording(box):
    """shop's quarantine cannot be re-asserted: its scan recorded its result,
    then raised. Its project expiry is still alerted, as not judged."""
    paths, pushover, _, docker = box
    seed_quarantine(paths, "shop")
    docker.fail = {"caddy_reload": 9, "compose_stop": 9}
    _suppress(paths, TODAY, project="shop")
    _scanned_yesterday(paths, "shop")
    assert cmd_security_scan(["shop"], paths) == 1
    [(title, body, priority)] = _sent(pushover, "project suppression expired")
    assert title.endswith("— not judged (scan failed)") and priority == 1
    assert "was not judged: its scan failed or was skipped" in body


def test_expiry_survives_trivy_going_missing_mid_run(box, monkeypatch):
    paths, pushover, carriers, _ = box
    _suppress(paths, TODAY, project="blog")
    _scanned_yesterday(paths, "shop", "wiki", "blog")

    def scan(ref, timeout):
        if ref.startswith("wiki"):
            raise TrivyNotInstalledError("trivy is gone")
        return scan_result(ref, [finding(CVE)] if ref.split("-")[0] in carriers else [])
    monkeypatch.setattr(security_scan_core, "scan_image", scan)
    (paths.state / "projects.txt").write_text("blog\nshop\nwiki\n")
    assert cmd_security_scan([], paths) == 1
    [(title, _, _)] = _sent(pushover, "project suppression expired")
    assert "[boxmunge:blog]" in title and title.endswith("— alerting only")


def test_unusable_record_partial_run_alerts_the_host_expiry_as_partial(box):
    """It cannot leave the expiry pending, so it alerts at once, saying the
    run judged only its own projects."""
    paths, pushover, *_ = box
    _suppress(paths, TODAY)
    _scanned_yesterday(paths, "blog")
    _corrupt_record(paths)
    assert cmd_security_scan(["blog"], paths) == 1
    [(title, body, priority)] = _sent(pushover, "host suppression expired")
    assert title.endswith("(partial: one scan's projects)") and priority == 1
    assert "blog [balanced]" in body


def test_expiry_after_a_run_judged_before_midnight_but_written_after(box, monkeypatch):
    """Run 1 judges by yesterday's clock (it started before 00:00 UTC) but
    writes today; run 2 must still replay the expiry from the judged date."""
    paths, pushover, *_ = box
    _suppress(paths, TODAY, project="shop")
    _scanned_yesterday(paths, "shop")
    monkeypatch.setattr(security_scan_core, "_today", lambda: TODAY - timedelta(days=1))
    monkeypatch.setattr(security_scan_core, "_now", lambda: NOW - timedelta(hours=4))
    cmd_security_scan(["shop"], paths)
    assert _sent(pushover, "expired") == []
    monkeypatch.setattr(security_scan_core, "_today", lambda: TODAY)
    monkeypatch.setattr(security_scan_core, "_now", lambda: NOW)
    cmd_security_scan(["shop"], paths)
    [(title, _, _)] = _sent(pushover, "project suppression expired")
    assert title.endswith("— quarantined")


@pytest.mark.parametrize(("posture", "title_end", "line"), [
    ("paranoid", "— will be quarantined", "will be quarantined (stopped)"),
    ("strict", "— will alert only", "will alert only and keep running"),
])
def test_suppressed_fixable_finding_is_warned(box, monkeypatch, posture, title_end, line):
    """A fixable finding under a suppression is IGNORED_FIXED, not
    SUPPRESSED: its expiry still changes what the policy does."""
    paths, pushover, *_ = box
    write_project(paths, "api", security={"posture": posture})
    (paths.state / "projects.txt").write_text("shop\nwiki\nblog\napi\n")
    monkeypatch.setattr(security_scan_core, "scan_image", lambda ref, timeout: scan_result(
        ref, [finding(CVE, fix="2")] if ref.startswith("api") else []))
    _suppress(paths, TODAY + timedelta(days=1), project="api")
    cmd_security_scan(["api"], paths)
    [(title, body, _)] = _sent(pushover, "project suppression expires")
    assert title.endswith(title_end)
    assert f"- api [{posture}; fix available] {line}" in body


def _pend(paths, detected_at: datetime) -> None:
    paths.suppression_notices.parent.mkdir(parents=True, exist_ok=True)
    paths.suppression_notices.write_text(json.dumps({"warned": [], "pending_host_expiries": [
        {"cve_id": CVE, "until": (TODAY - timedelta(days=2)).isoformat(),
         "detected_at": detected_at.isoformat()}]}))


def test_overdue_pending_host_expiry_is_alerted_by_a_partial_run(box):
    """No full nightly has completed within SCAN_MAX_AGE of the expiry being
    found: a partial run alerts it, as partial, once."""
    paths, pushover, *_ = box
    _suppress(paths, TODAY - timedelta(days=2))
    _pend(paths, NOW - timedelta(hours=37))
    cmd_security_scan(["blog"], paths)
    [(title, body, priority)] = _sent(pushover, "host suppression expired")
    assert title.endswith("(partial: one scan's projects)") and priority == 1
    assert "No full nightly scan has completed since" in body
    assert "blog [balanced]" in body
    assert read_record(paths).pending == {}
    pushover.clear()
    cmd_security_scan(["blog"], paths)
    assert _sent(pushover, "expired") == []


def test_recent_pending_host_expiry_waits_for_the_fleet_run(box):
    paths, pushover, *_ = box
    _suppress(paths, TODAY - timedelta(days=2))
    _pend(paths, NOW - timedelta(hours=2))
    cmd_security_scan(["blog"], paths)
    assert _sent(pushover, "expired") == []
    assert len(read_record(paths).pending) == 1
