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
import yaml

from boxmunge.bind_sources import BindSourceError
from boxmunge.commands import quarantine_lift, security_actions, security_scan_core
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition
from boxmunge.cve.quarantine import is_quarantined, quarantine_action_complete
from boxmunge.cve.scanner import ScannerError, Severity
from boxmunge.docker_run import DockerError
from boxmunge.pause import is_paused, write_paused_state
from boxmunge.release import mark_live
from boxmunge.release_txn import open_txn
from boxmunge.state import write_state
from tests.test_commands.cve_helpers import (
    CRIT, Docker, Pushover, finding, make_box, render_site, scan_result, seed_quarantine,
)

_CVE = CRIT.cve_id  # quarantined by seed_quarantine
AWAITING_TITLE = "no fix yet — site stays up, nothing to do now"
LIFTED_TITLE = "Quarantine lifted"


def _kev(*ids: str) -> KevCatalog:
    return KevCatalog(frozenset(ids), datetime.now(timezone.utc), datetime.now(timezone.utc), 'test')


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
    assert "still down" in title


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
    _scan(paths, KevCatalog(frozenset(), None, None, None))
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


@pytest.mark.parametrize("error", [
    BindSourceError("cannot read state/deploy/demo.binds.json"),
    DockerError("docker image rm timed out"),
])
def test_an_overlay_that_cannot_be_regenerated_fails_the_lift_before_caddy(
        box, monkeypatch, error) -> None:
    paths, pushover = box()
    seed_quarantine(paths)

    def fail(paths, manifest, component=None):
        raise error

    monkeypatch.setattr(quarantine_lift, "prepare_compose_override", fail)
    with pytest.raises(RuntimeError, match="automatic quarantine lift failed.*Failed to "
                                           "regenerate the compose overlay"):
        _scan(paths)
    assert is_quarantined("demo", paths) and quarantine_action_complete("demo", paths)
    assert "caddy_reload" not in paths.docker.calls and "compose_up" not in paths.docker.calls
    assert not _titles(pushover, LIFTED_TITLE)


def test_a_failed_lift_puts_the_maintenance_page_back_and_fails_loudly(box) -> None:
    """`compose up` fails after the routing switch: the quarantine is
    re-asserted at once, not left serving a 502 until the next scan."""
    paths, pushover = box()
    seed_quarantine(paths)
    paths.docker.fail["compose_up"] = 1
    with pytest.raises(RuntimeError, match="automatic quarantine lift failed.*maintenance "
                                           "page is back"):
        _scan(paths)
    assert paths.docker.calls == ["caddy_reload", "compose_up", "caddy_reload", "compose_stop"]
    assert is_quarantined("demo", paths) and quarantine_action_complete("demo", paths)
    assert "maintenance" in paths.project_caddy_site("demo").read_text().lower()
    assert not _titles(pushover, LIFTED_TITLE)
    _scan(paths)  # the next scan retries it
    assert not is_quarantined("demo", paths)
    assert _titles(pushover, LIFTED_TITLE)


# ---- only balanced lifts on its own ----


def test_relaxed_keeps_a_kev_quarantine_whose_fix_is_published_not_deployed(box) -> None:
    """Under relaxed a fixable KEV finding stops quarantining, but the image
    running is still the exploited one: only a deploy or resume lifts it."""
    paths, pushover = box("relaxed")
    seed_quarantine(paths)
    paths.found = [finding(fix="3.0.15-1")]
    fd = _scan(paths, _kev(_CVE)).decisions[0].findings[0]
    assert fd.disposition is Disposition.IGNORED_FIXED and fd.kev_listed
    assert is_quarantined("demo", paths) and "compose_up" not in paths.docker.calls
    assert not _titles(pushover, LIFTED_TITLE)


@pytest.mark.parametrize("posture", ["relaxed", "strict", "paranoid"])
def test_other_postures_never_lift_on_their_own(box, posture) -> None:
    """A distro re-triage (here: nothing found any more) is not evidence the
    running images are safe under a posture whose rules did not change."""
    paths, pushover = box(posture)
    seed_quarantine(paths)
    paths.found = [finding(sev=Severity.LOW)] if posture != "relaxed" else []
    _scan(paths)
    assert is_quarantined("demo", paths) and "compose_up" not in paths.docker.calls
    assert not _titles(pushover, LIFTED_TITLE)


def test_balanced_with_any_kev_finding_keeps_the_quarantine(box, tmp_path) -> None:
    """Opted out, a KEV finding runs at risk instead of quarantining: it
    still is no reason to lift a quarantine on the scan's own say-so."""
    paths, pushover = box()
    data = yaml.safe_load(paths.project_manifest("demo").read_text())
    data["security"] = {"posture": "balanced", "dangerously_disable_quarantine": True}
    paths.project_manifest("demo").write_text(yaml.safe_dump(data))
    seed_quarantine(paths)
    fd = _scan(paths, _kev(_CVE)).decisions[0].findings[0]
    assert fd.disposition is Disposition.STILL_RUNNING_AT_RISK and fd.kev_listed
    assert is_quarantined("demo", paths)
    assert not _titles(pushover, LIFTED_TITLE)


# ---- what must not be started from a scan ----


def test_a_monitor_stopped_project_has_its_quarantine_lifted_but_stays_down(box) -> None:
    """Started, it would stay monitor-stopped: unwatched by the monitor and
    skipped by container-update. `recover` is the way back, as after
    `security resume` (the one rule: quarantine_lift.start_hold)."""
    paths, pushover = box()
    seed_quarantine(paths)
    write_state(paths.project_health_state("demo"), {
        "status": "critical_stopped", "stopped_at": "2026-10-01T03:00:00+00:00"})
    assert is_monitor_stopped("demo", paths)
    scan = _scan(paths)
    assert scan.lifted and not is_quarantined("demo", paths)
    assert paths.docker.calls == []   # nothing started, the maintenance page stays
    assert is_monitor_stopped("demo", paths)
    [(title, body, _)] = [m for m in pushover.sent if LIFTED_TITLE in m[0]]
    assert "still down" in title and "boxmunge recover demo" in body


def test_a_userns_migration_keeps_the_quarantine(box) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    paths.userns_marker.parent.mkdir(parents=True, exist_ok=True)
    paths.userns_marker.write_text("userns-migrate\n")
    scan = _scan(paths)
    assert scan.kept == ("quarantine kept: a userns migration is in progress; the scan "
                         "after it lifts it")
    assert is_quarantined("demo", paths) and "compose_up" not in paths.docker.calls
    assert not _titles(pushover, LIFTED_TITLE)


def test_a_corrupt_health_state_is_that_projects_problem(tmp_path, monkeypatch) -> None:
    """The fleet scan reports it, alerts and exits 1, and scans the rest."""
    paths = make_box(tmp_path, projects=("aaa", "bbb"), security={"posture": "balanced"})
    monkeypatch.setattr(security_scan_core, "scan_image",
                        lambda ref, timeout: scan_result(ref, [CRIT]))
    monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
    Docker(monkeypatch)
    pushover = Pushover(monkeypatch, paths)
    seed_quarantine(paths, "aaa")
    paths.project_health_state("aaa").parent.mkdir(parents=True, exist_ok=True)
    paths.project_health_state("aaa").write_text("{not json")
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    assert cmd_security_scan([], paths) == 1
    [(_, body, priority)] = [m for m in pushover.sent if "CVE scan incomplete" in m[0]]
    assert priority == 1 and "aaa" in body and "bbb" not in body
    assert str(paths.project_health_state("aaa")) in body
    assert is_quarantined("aaa", paths)
    assert paths.project_scan_state("bbb").exists()


def test_a_failed_put_back_leaves_the_record_incomplete(box) -> None:
    paths, _ = box()
    seed_quarantine(paths)
    paths.docker.fail.update({"compose_up": 1, "compose_stop": 1})
    with pytest.raises(RuntimeError, match="putting the maintenance page back failed too"):
        _scan(paths)
    assert is_quarantined("demo", paths) and not quarantine_action_complete("demo", paths)


def test_the_scan_reports_the_parsed_posture(box) -> None:
    paths, _ = box()
    data = yaml.safe_load(paths.project_manifest("demo").read_text())
    data["security"] = {"posture": "Balanced"}
    paths.project_manifest("demo").write_text(yaml.safe_dump(data))
    assert _scan(paths).posture == "balanced"


def test_an_open_install_refuses_the_lift(box) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    mark_live(paths, "demo", "demo-v1")
    open_txn(paths, "demo", source="bundle", ref="demo-v2", replaced_ref="demo-v1",
             staged_id=None, snapshot="")
    with pytest.raises(RuntimeError, match="automatic quarantine lift failed.*demo-v2"):
        _scan(paths)
    assert is_quarantined("demo", paths) and "compose_up" not in paths.docker.calls
    assert not _titles(pushover, LIFTED_TITLE)


# ---- the fleet scan ----


def test_the_fleet_scan_reports_the_lift_and_exits_0(box, monkeypatch, capsys) -> None:
    paths, _ = box()
    seed_quarantine(paths)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    assert cmd_security_scan([], paths) == 0
    assert f"demo: quarantine lifted ({_CVE})" in capsys.readouterr().out
    assert not is_quarantined("demo", paths)


def test_a_failed_lift_fails_the_fleet_scan_and_alerts(box, monkeypatch) -> None:
    paths, pushover = box()
    seed_quarantine(paths)
    paths.docker.fail["compose_up"] = 1
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    assert cmd_security_scan([], paths) == 1
    [(title, body, priority)] = [m for m in pushover.sent if "CVE scan incomplete" in m[0]]
    assert priority == 1 and "automatic quarantine lift failed" in body
    assert is_quarantined("demo", paths)
