# SPDX-License-Identifier: Apache-2.0
"""Balanced quarantines only on CISA KEV (0.11.2).

An unfixable, distro-rated, network-reachable finding over balanced's gate is
AWAITING_FIX: alerted once, the site stays up. When its fix lands the
fixable alert fires; when it is KEV-listed it quarantines. A quarantine the
old rule took is lifted by the next scan that finds nothing quarantine-level,
with no deploy. The real scan, policy, quarantine and alerting code run; only
Docker and Trivy are stubbed.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from boxmunge.commands import quarantine_lift, security_scan_core
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import is_quarantined, quarantine_action_complete
from boxmunge.cve.scanner import ScannerError
from boxmunge.pause import is_paused, write_paused_state
from tests.test_commands.cve_helpers import (
    CRIT, Docker, Pushover, finding, make_box, render_site, scan_result, seed_quarantine,
)

_CVE = CRIT.cve_id  # quarantined by seed_quarantine
AWAITING_TITLE = "no fix yet — site stays up, nothing to do now"
LIFTED_TITLE = "Quarantine lifted"


def _kev(*ids: str) -> KevCatalog:
    return KevCatalog(frozenset(ids), datetime.now(timezone.utc))


@pytest.fixture
def box(tmp_path, monkeypatch):
    """'demo' on ``posture``; ``found`` is what every image scan reports."""
    def build(posture: str = "balanced"):
        paths = make_box(tmp_path, security={"posture": posture})
        paths.found = [CRIT]
        monkeypatch.setattr(security_scan_core, "scan_image",
                            lambda ref, timeout: scan_result(ref, paths.found))
        monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
        monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                            lambda p, m, component=None: None)
        paths.docker = Docker(monkeypatch)
        return paths, Pushover(monkeypatch, paths)
    return build


def _scan(paths, kev: KevCatalog | None = None):
    return scan_one_project(paths, "demo", in_grace=False, kev=kev or _kev())


def _titles(pushover, words: str) -> list[str]:
    return [t for t in pushover.titles() if words in t]


# ---- awaiting a fix ----


def test_unfixable_critical_stays_up_and_alerts_once(box) -> None:
    paths, pushover = box()
    fd = _scan(paths).decisions[0].findings[0]
    assert fd.disposition is Disposition.AWAITING_FIX
    assert not is_quarantined("demo", paths)
    [(title, body, priority)] = pushover.sent
    assert AWAITING_TITLE in title and priority == 0
    for words in ("no fix exists yet", "not known to be exploited", "nothing needs doing now",
                  "when a fix lands", "listed as actively exploited",
                  "`security.posture: strict` takes such findings down", _CVE):
        assert words in body
    for _ in range(2):  # daily scans: silent while nothing changes
        pushover.clear()
        _scan(paths)
        assert pushover.sent == []


def test_the_fix_landing_alerts_with_the_rebuild_advice(box) -> None:
    paths, pushover = box()
    _scan(paths)
    pushover.clear()
    paths.found = [finding(fix="3.0.15-1")]
    fd = _scan(paths).decisions[0].findings[0]
    assert fd.disposition is Disposition.IGNORED_FIXED and fd.fix_would_quarantine
    [(title, body, priority)] = pushover.sent
    assert "fixable CVE finding" in title and "rebuild to apply the fix" in title
    assert priority == 0 and "build: {pull: true}" in body and "redeploy" in body
    assert not is_quarantined("demo", paths)
    pushover.clear()
    _scan(paths)
    assert pushover.sent == []


def test_a_kev_listing_quarantines_it(box) -> None:
    paths, pushover = box()
    _scan(paths)
    pushover.clear()
    fd = _scan(paths, _kev(_CVE)).decisions[0].findings[0]
    assert fd.disposition is Disposition.QUARANTINE and fd.kev_listed
    assert is_quarantined("demo", paths)
    [(title, _, priority)] = [m for m in pushover.sent if "QUARANTINED" in m[0]]
    assert priority == 1 and "CISA KEV" in title


def test_strict_takes_the_same_finding_down(box) -> None:
    paths, pushover = box("strict")
    assert _scan(paths).decisions[0].findings[0].disposition is Disposition.QUARANTINE
    assert is_quarantined("demo", paths)
    assert _titles(pushover, "QUARANTINED") and not _titles(pushover, AWAITING_TITLE)


# ---- lifting a quarantine the old rule took ----


def test_a_quarantine_the_old_rule_took_lifts_at_the_next_scan(box) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    _scan(paths)
    assert not is_quarantined("demo", paths)
    assert paths.docker.calls == ["caddy_reload", "compose_up"]
    assert paths.docker.kwargs["compose_up"]["build"] is False
    [(title, body, priority)] = [m for m in pushover.sent if LIFTED_TITLE in m[0]]
    assert "back online" in title and _CVE in title and priority == 0
    assert "The posture rules changed in boxmunge 0.11.2" in body
    assert "only on actively exploited (CISA KEV)" in body and "Smoke test: OK" in body
    pushover.clear()
    _scan(paths)
    assert not _titles(pushover, LIFTED_TITLE) and not is_quarantined("demo", paths)


def test_a_failed_smoke_test_after_the_lift_is_priority_1(box) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    paths.docker.smoke = (False, "HTTP 502")
    _scan(paths)
    [(title, body, priority)] = [m for m in pushover.sent if LIFTED_TITLE in m[0]]
    assert "smoke test FAILED" in title and "HTTP 502" in body and priority == 1


def test_a_paused_project_has_its_quarantine_lifted_but_stays_down(box) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    write_paused_state("demo", paths)
    _scan(paths)
    assert not is_quarantined("demo", paths) and is_paused("demo", paths)
    assert "compose_up" not in paths.docker.calls
    [title] = _titles(pushover, LIFTED_TITLE)
    assert "still paused" in title


def test_a_still_kev_listed_finding_keeps_the_quarantine(box) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    _scan(paths, _kev(_CVE))
    assert is_quarantined("demo", paths) and quarantine_action_complete("demo", paths)
    assert "compose_up" not in paths.docker.calls
    assert not _titles(pushover, LIFTED_TITLE)


def test_a_stale_kev_catalog_never_lifts(box) -> None:
    """A stale catalog reads as "nothing exploited": it cannot clear a site."""
    paths, pushover = box()
    seed_quarantine(paths)
    _scan(paths, KevCatalog(frozenset(), None))
    assert is_quarantined("demo", paths)
    assert paths.docker.calls == ["caddy_reload", "compose_stop"]
    assert not _titles(pushover, LIFTED_TITLE)


def test_an_incomplete_scan_never_lifts(box, monkeypatch) -> None:
    paths, pushover = box()
    seed_quarantine(paths)

    def flaky(ref, timeout):
        raise ScannerError("registry unreachable")

    monkeypatch.setattr(security_scan_core, "scan_image", flaky)
    with pytest.raises(RuntimeError, match="All images failed to scan"):
        _scan(paths)
    assert is_quarantined("demo", paths)
    assert not _titles(pushover, LIFTED_TITLE)


def test_strict_keeps_the_quarantine(box) -> None:
    paths, pushover = box("strict")
    seed_quarantine(paths)
    _scan(paths)
    assert is_quarantined("demo", paths)
    assert not _titles(pushover, LIFTED_TITLE)


def test_a_failed_lift_keeps_the_record_and_fails_the_scan_loudly(box) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    paths.docker.fail["compose_up"] = 1
    with pytest.raises(RuntimeError, match="automatic quarantine lift failed"):
        _scan(paths)
    assert is_quarantined("demo", paths)
    assert not _titles(pushover, LIFTED_TITLE)
    _scan(paths)  # the next scan retries it
    assert not is_quarantined("demo", paths)
    assert _titles(pushover, LIFTED_TITLE)
