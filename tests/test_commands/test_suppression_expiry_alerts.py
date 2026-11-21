# SPDX-License-Identifier: Apache-2.0
"""Suppression expiry warnings and expiry alerts through the real fleet scan,
policy and enforcement (Docker and Trivy stubbed)."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
import yaml

from boxmunge.commands import security_actions, security_scan_core
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.cve.breaker import read_held
from boxmunge.cve.exploited import ExploitedIndex, ExploitedSource
from boxmunge.cve.policy import ProjectDecision
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scan_state import write_scan_state
from boxmunge.cve.suppression_warned import read_warned
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, scan_result, write_project,
)

CVE = "CVE-2026-57433"
TODAY = datetime.now(timezone.utc).date()


@pytest.fixture
def box(tmp_path, monkeypatch):
    """shop (paranoid) and blog (balanced) carry CVE; wiki (paranoid) does
    not. Returns (paths, pushover, carriers): ``carriers`` is the set of
    projects whose image carries CVE, which a test may change."""
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
    Docker(monkeypatch)
    return paths, Pushover(monkeypatch, paths), carriers


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
    paths, pushover, _ = box
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
    paths, pushover, _ = box
    _suppress(paths, TODAY + timedelta(days=3))
    cmd_security_scan([], paths)
    assert _sent(pushover, "expires") == []
    assert read_warned(paths) == {}


def test_single_project_scan_leaves_the_host_warning_to_the_fleet_run(box):
    """It judges one project; the host warning needs the whole fleet."""
    paths, pushover, _ = box
    _suppress(paths, TODAY + timedelta(days=1))
    cmd_security_scan(["shop"], paths)
    assert _sent(pushover, "expires") == []
    cmd_security_scan([], paths)
    assert len(_sent(pushover, "host suppression expires")) == 1


def test_host_warning_with_no_carrier_is_normal_priority(box):
    paths, pushover, carriers = box
    carriers.clear()
    _suppress(paths, TODAY + timedelta(days=2))
    cmd_security_scan([], paths)
    [(title, body, priority)] = _sent(pushover, "host suppression expires")
    assert title.endswith("— no project affected") and priority == 0
    assert "- 3 projects have no finding for it (no effect)" in body


def test_project_warning_once_and_again_for_an_extension(box):
    """Once per (CVE, scope, project, until): extended, the new date is a new
    window, warned again when it nears."""
    paths, pushover, _ = box
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
    assert {k[3] for k in read_warned(paths)} == {
        (TODAY + timedelta(days=1)).isoformat(), (TODAY + timedelta(days=2)).isoformat()}


def test_extended_after_the_warning_never_expires(box):
    """The scan dates straddle the old until; the suppression now runs later."""
    paths, pushover, _ = box
    _suppress(paths, TODAY + timedelta(days=30), project="shop")
    _scanned_yesterday(paths, "shop", "wiki", "blog")
    cmd_security_scan([], paths)
    assert _sent(pushover, "expired") == []


def test_unusable_warning_record_fails_the_run_loudly(box):
    paths, pushover, _ = box
    _suppress(paths, TODAY + timedelta(days=2))
    paths.suppression_warnings.parent.mkdir(parents=True, exist_ok=True)
    paths.suppression_warnings.write_text("{not json")
    assert cmd_security_scan([], paths) == 1
    assert _sent(pushover, "expires") == []
    [(_, body, _)] = _sent(pushover, "CVE scan incomplete")
    assert "suppression expiry warnings not sent" in body


# ---------- the expiry alert ----------


def test_host_expiry_says_what_happened_once_per_run(box):
    paths, pushover, _ = box
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
    paths, pushover, carriers = box
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
    paths, pushover, _ = box
    _suppress(paths, TODAY, project="wiki")
    _scanned_yesterday(paths, "wiki")
    cmd_security_scan(["wiki"], paths)
    [(title, body, priority)] = _sent(pushover, "project suppression expired")
    assert "[boxmunge:wiki]" in title and title.endswith("— no effect")
    assert priority == 0
    assert "no finding for it in the project's images" in body


def test_vulncheck_listing_is_judged_per_posture(box, monkeypatch):
    """A VulnCheck-only listing: paranoid ignores the suppression already and
    quarantines; under balanced the suppression applies, and its expiry only
    alerts (the site stays up)."""
    paths, pushover, _ = box
    monkeypatch.setattr(security_scan_core, "load_exploited", lambda p, today, cisa=None:
                        ExploitedIndex({CVE: frozenset({ExploitedSource.VULNCHECK})}, {}))
    _suppress(paths, TODAY + timedelta(days=2))
    cmd_security_scan([], paths)
    [(_, body, _)] = _sent(pushover, "host suppression expires")
    assert "will alert only and keep running: blog [balanced; known exploited (VulnCheck" in body
    assert "will be quarantined (stopped): shop [paranoid; known exploited (VulnCheck" in body


def test_project_suppression_outliving_the_host_one_keeps_it_covered(box):
    paths, pushover, _ = box
    _suppress(paths, TODAY + timedelta(days=1))
    _suppress(paths, TODAY + timedelta(days=20), project="shop")
    cmd_security_scan([], paths)
    [(title, body, _)] = _sent(pushover, "host suppression expires")
    assert "- 1 project stays covered by another suppression: shop [paranoid]" in body
    assert title.endswith("— 1 project will alert only")
