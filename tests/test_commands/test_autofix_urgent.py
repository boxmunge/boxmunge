# SPDX-License-Identifier: Apache-2.0
"""The urgent autofix flow through the real scan, quarantine and alerting
code (CVE autofix flowcharts, chart 1, tables A and B). Trivy, the image
probe, the Docker primitives and the patch runner itself are stubbed."""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.commands import (
    autofix_urgent, autofix_urgent_scan, kev_watch, quarantine_lift, security_actions,
    security_scan_core,
)
from boxmunge.cve import autofix_run
from boxmunge.cve.alerting import PERSISTENCE_CAVEAT
from boxmunge.cve.autofix_build import NotPatchable, Patchable
from boxmunge.cve.autofix_policy import AUTOFIX_URGENT_BUDGET
from boxmunge.cve.autofix_record import (
    PackageChange, PatchRecord, read_autofixing, read_queue_entry,
)
from boxmunge.cve.autofix_run import AutofixOutcome
from boxmunge.cve.exploited import ExploitedIndex, ExploitedSource
from boxmunge.cve.fleet_lock import FleetLockBusy, fleet_lock
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.fileutil import project_lock
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, render_site, scan_and_send, scan_result,
)

CVE = "CVE-2026-0001"
CISA = frozenset({ExploitedSource.CISA})
VULNCHECK = frozenset({ExploitedSource.VULNCHECK})


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Runner:
    """Stands in for autofix_run.autofix_project_locked."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...], str, datetime]] = []
        self.outcome: AutofixOutcome | None = None

    def __call__(self, paths, project, findings, *, trigger, deadline):
        autofix_run._require_lock_held(paths, project)
        self.calls.append((project, tuple(fd.finding.cve_id for fd in findings), trigger,
                           deadline))
        if self.outcome is not None:
            return self.outcome
        record = PatchRecord(
            project=project, service="web", base_ref=f"{project}-web:1",
            base_digest="sha256:" + "b" * 64,
            patched_ref=f"boxmunge.invalid/{project}/web:autofix-aaaaaaaaaaaa",
            patched_image_id="sha256:" + "a" * 64,
            packages=(PackageChange("openssl", "1", "2"),), cves=(CVE,), created_at=_now(),
            trigger="urgent")
        return AutofixOutcome(True, None, "patched web", (record,))


class Box:
    def __init__(self, tmp_path, monkeypatch, security: dict, *, listed=CISA,
                 cvss: float | None = 9.8, projects=("demo",)) -> None:
        self.paths = make_box(tmp_path, projects=projects, security=security)
        self.found = [replace(finding(CVE, fix="2"), cvss_score=cvss)]
        self.listed = listed
        self.monkeypatch = monkeypatch
        monkeypatch.setattr(security_scan_core, "scan_image",
                            lambda ref, timeout: scan_result(ref, self.found))
        monkeypatch.setattr(security_scan_core, "load_exploited", lambda p, today, cisa=None:
                            ExploitedIndex({CVE: self.listed} if self.listed else {}, {}))
        self.probed: list[str] = []
        self.patchability = Patchable("apt", "")
        monkeypatch.setattr(autofix_urgent_scan, "probe", self._probe)
        monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
        monkeypatch.setattr(quarantine_lift, "prepare_compose_override",
                            lambda p, m, component=None: None)
        self.docker = Docker(monkeypatch)
        self.pushover = Pushover(monkeypatch, self.paths)
        self.runner = Runner()
        monkeypatch.setattr(autofix_urgent, "autofix_project_locked", self.runner)

    def _probe(self, ref):
        self.probed.append(ref)
        return self.patchability

    def scan(self, project: str = "demo"):
        now = _now()
        return scan_and_send(self.paths, project, kev=KevCatalog(frozenset(), now, now, "t"))

    def run(self, now: datetime | None = None):
        return autofix_urgent.run_urgent_queue(self.paths, now or _now())

    def sent(self, words: str) -> list[tuple[str, str, int]]:
        return [s for s in self.pushover.sent if words in s[0]]


def _box(tmp_path, monkeypatch, posture: str, **kw) -> Box:
    return Box(tmp_path, monkeypatch, {"posture": posture}, **kw)


# ---------- chart 1 and table A, per posture ----------


@pytest.mark.parametrize(("posture", "listed", "cvss", "dark"), [
    pytest.param("relaxed", CISA, 9.8, False, id="relaxed-kev-9.8-up"),
    pytest.param("balanced", CISA, 7.5, False, id="balanced-kev-7.5-up"),
    pytest.param("balanced", CISA, 9.8, True, id="balanced-kev-9.8-dark-then-lifted"),
    pytest.param("strict", CISA, 7.5, True, id="strict-kev-dark"),
    pytest.param("strict", VULNCHECK, 9.8, False, id="strict-vulncheck-only-up"),
    pytest.param("paranoid", frozenset(), 5.0, True, id="paranoid-fixable-at-gate-dark"),
])
def test_urgent_flow_matches_posture_charts(tmp_path, monkeypatch, posture, listed, cvss,
                                            dark) -> None:
    box = _box(tmp_path, monkeypatch, posture, listed=listed, cvss=cvss)
    before = _now()
    box.scan()
    paths = box.paths
    assert is_quarantined("demo", paths) is dark
    assert read_autofixing(paths, "demo").downtime is dark
    entry = read_queue_entry(paths, "demo")
    assert entry.cves == (CVE,) and entry.downtime is dark
    assert before <= entry.detected_at <= _now()
    [started] = box.sent("patching")
    site = "site down while patching" if dark else "site up"
    assert started[0].endswith(f"[boxmunge:demo] {CVE} found on demo, patching ({site})")
    assert started[2] == 0
    assert box.sent("QUARANTINED") == ([box.sent("QUARANTINED")[0]] if dark else [])

    [outcome] = box.run()
    assert outcome.ok
    [(project, cves, trigger, deadline)] = box.runner.calls
    assert (project, cves, trigger) == ("demo", (CVE,), "urgent")
    assert deadline == entry.detected_at + AUTOFIX_URGENT_BUDGET
    assert not is_quarantined("demo", paths)
    assert read_queue_entry(paths, "demo") is None and read_autofixing(paths, "demo") is None
    [patched] = box.sent("Autofix patched")
    assert patched[2] == 0
    assert ("quarantine is lifted" in patched[1]) is dark
    assert box.sent("Quarantine lifted") == []   # the patched notice says it, once
    assert box.docker.calls.count("compose_up") == (1 if dark else 0)


def test_failure_applies_table_b_and_alerts_step(tmp_path, monkeypatch) -> None:
    """Balanced, full KEV below 9: up while patched, quarantined when it fails."""
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    assert not is_quarantined("demo", box.paths)
    box.runner.outcome = AutofixOutcome(False, "build", "the mirror is unreachable", ())
    box.run()
    assert is_quarantined("demo", box.paths)
    [failed] = box.sent("Autofix FAILED")
    title, body, priority = failed
    assert priority == 1 and "at the build step" in title and CVE in title
    assert "the mirror is unreachable" in body and "quarantined now" in body
    assert "mixed" not in body
    assert read_queue_entry(box.paths, "demo") is None
    assert read_autofixing(box.paths, "demo") is None


@pytest.mark.parametrize(("posture", "listed", "expect"), [
    pytest.param("balanced", VULNCHECK, "stays up", id="balanced-vulncheck-stays-up"),
    pytest.param("relaxed", CISA, "stays up", id="relaxed-kev-with-fix-stays-up"),
    pytest.param("strict", CISA, "stays quarantined", id="strict-kev-stays-dark"),
    pytest.param("paranoid", VULNCHECK, "stays quarantined", id="paranoid-vulncheck-dark"),
])
def test_table_b_fallback_per_posture(tmp_path, monkeypatch, posture, listed, expect) -> None:
    box = _box(tmp_path, monkeypatch, posture, listed=listed)
    box.scan()
    dark = is_quarantined("demo", box.paths)
    stops = box.docker.calls.count("compose_stop")
    box.runner.outcome = AutofixOutcome(False, "health", "web is unhealthy", ())
    box.run()
    assert is_quarantined("demo", box.paths) is dark is (expect == "stays quarantined")
    if dark:   # the rollback started the containers: they are stopped again
        assert box.docker.calls.count("compose_stop") == stops + 1
    [failed] = box.sent("Autofix FAILED")
    assert "at the health step" in failed[0] and expect in failed[1]


def test_running_at_risk_stays_up_when_quarantine_is_disabled(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, {"posture": "strict",
                                       "dangerously_disable_quarantine": True})
    box.scan()
    assert not is_quarantined("demo", box.paths)
    assert read_queue_entry(box.paths, "demo").downtime is False
    box.runner.outcome = AutofixOutcome(False, "scan", "still vulnerable", ())
    box.run()
    assert not is_quarantined("demo", box.paths)
    [failed] = box.sent("Autofix FAILED")
    assert "running at risk" in failed[1]


def test_an_incomplete_rollback_says_the_project_may_be_mixed(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    box.runner.outcome = AutofixOutcome(
        False, "swap", "compose up failed; rollback could not recreate", (),
        ("rollback could not recreate the previous containers: DockerError: boom",))
    box.run()
    [failed] = box.sent("Autofix FAILED")
    assert "may be left mixed" in failed[1] and "DockerError: boom" in failed[1]
    assert "boxmunge status demo" in failed[1]
    assert is_quarantined("demo", box.paths)   # quarantined regardless


# ---------- when autofix cannot help ----------


def test_autofix_off_queues_nothing_and_says_why(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, {"posture": "balanced", "autofix": False})
    box.scan()
    assert is_quarantined("demo", box.paths)
    assert read_queue_entry(box.paths, "demo") is None
    assert read_autofixing(box.paths, "demo") is None
    assert box.probed == [] and box.sent("patching") == []
    [quarantined] = box.sent("QUARANTINED")
    assert "autofix is off for this project" in quarantined[1]
    assert box.run() == [] and box.runner.calls == []


@pytest.mark.parametrize(("posture", "alert"), [
    pytest.param("balanced", "QUARANTINED", id="quarantine-alert"),
    pytest.param("relaxed", "KEV", id="at-risk-alert"),
])
def test_not_patchable_alert_carries_probe_reason(tmp_path, monkeypatch, posture,
                                                  alert) -> None:
    box = _box(tmp_path, monkeypatch, posture)
    box.patchability = NotPatchable("no supported package manager (apk or apt) in the image")
    box.scan()
    assert read_queue_entry(box.paths, "demo") is None
    assert is_quarantined("demo", box.paths) is (posture == "balanced")
    [sent] = [s for s in box.sent(alert) if CVE in s[0]]
    assert "no supported package manager (apk or apt) in the image" in sent[1]
    assert box.sent("patching") == []


def test_another_finding_that_keeps_the_site_down_blocks_the_patch(tmp_path,
                                                                    monkeypatch) -> None:
    """The swap would start a project something else keeps quarantined."""
    box = _box(tmp_path, monkeypatch, "paranoid")
    box.found.append(finding("CVE-2026-0002", pkg="libxml2"))   # no fix: dark until fixed
    box.scan()
    assert is_quarantined("demo", box.paths)
    assert read_queue_entry(box.paths, "demo") is None
    [quarantined] = box.sent("QUARANTINED")
    assert "CVE-2026-0002 in libxml2 also takes the site down" in quarantined[1]


def test_urgent_runs_during_probation(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.paths.probation.parent.mkdir(parents=True, exist_ok=True)
    box.paths.probation.write_text(json.dumps({
        "version": "0.12.0", "previous_slot": "a", "started_at": _now().isoformat(),
        "expires_at": (_now() + timedelta(hours=6)).isoformat()}))
    box.scan()
    [outcome] = box.run()
    assert outcome.ok and len(box.runner.calls) == 1


def test_patched_alert_carries_the_persistence_caveat(tmp_path, monkeypatch) -> None:
    assert PERSISTENCE_CAVEAT == ("Autofix replaced the vulnerable code. It does not clean "
                                  "persistent data or prove nothing was planted before the "
                                  "patch.")
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    box.run()
    [patched] = box.sent("Autofix patched")
    assert patched[1].endswith(PERSISTENCE_CAVEAT)
    assert "openssl 1 → 2" in patched[1]


# ---------- the queue ----------


def test_a_passed_deadline_starts_nothing_and_falls_back(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    box.run(_now() + AUTOFIX_URGENT_BUDGET + timedelta(seconds=1))
    assert box.runner.calls == []
    assert is_quarantined("demo", box.paths)
    [failed] = box.sent("Autofix FAILED")
    assert "at the budget step" in failed[0] and "had not started" in failed[1]


def test_a_busy_project_is_left_for_the_next_run(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.paths.log_file.parent.mkdir(parents=True, exist_ok=True)
    box.scan()
    with project_lock("demo", box.paths):
        assert box.run() == []
    assert read_queue_entry(box.paths, "demo") is not None
    assert "held by another operation" in box.paths.log_file.read_text()
    [outcome] = box.run()
    assert outcome.ok


def test_a_queued_finding_the_stored_scan_no_longer_has_is_dropped(tmp_path,
                                                                  monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    box.found = []
    box.scan()   # a later scan finds it gone; the queue entry is not trusted on its own
    assert box.run() == [] and box.runner.calls == []
    assert read_queue_entry(box.paths, "demo") is None
    assert read_autofixing(box.paths, "demo") is None


def test_a_malformed_entry_is_alerted_and_the_rest_still_run(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed", projects=("blog", "shop"))
    box.scan("blog")
    box.scan("shop")
    bad = box.paths.project_autofix_queue("blog")
    bad.write_text("{not json")
    [outcome] = box.run()
    assert outcome.ok and [c[0] for c in box.runner.calls] == ["shop"]
    [problem] = box.sent("could not run")
    assert problem[2] == 1 and str(bad) in problem[1]


def test_a_rescan_keeps_the_queued_detection_time(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    first = read_queue_entry(box.paths, "demo")
    box.scan()
    assert read_queue_entry(box.paths, "demo") == first
    assert not is_quarantined("demo", box.paths)   # still up while it waits
    assert len(box.sent("patching")) == 1


# ---------- the callers ----------


def _fleet(box: Box):
    now = _now()
    return security_actions.scan_projects(box.paths, ["demo"],
                                          kev=KevCatalog(frozenset(), now, now, "t"))


@pytest.mark.parametrize(("cvss", "dark"), [(7.5, False), (9.8, True)])
def test_the_fleet_run_holds_back_only_the_up_while_patching_quarantine(
        tmp_path, monkeypatch, cvss, dark) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=cvss)
    run = _fleet(box)
    assert is_quarantined("demo", box.paths) is dark
    assert not run.held


def test_the_fleet_quarantine_alert_carries_why_autofix_cannot_help(tmp_path,
                                                                    monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced")
    box.patchability = NotPatchable("no shell or package manager in the image")
    _fleet(box)
    [quarantined] = box.sent("QUARANTINED")
    assert "no shell or package manager in the image" in quarantined[1]


def _holds_fleet_lock(paths) -> bool:
    try:
        with fleet_lock(paths):
            return False
    except FleetLockBusy:
        return True


@pytest.mark.parametrize(("ok", "rc"), [(True, 0), (False, 2)])
def test_the_fleet_scan_runs_the_queue_under_its_lock(tmp_path, monkeypatch, ok, rc) -> None:
    """A patch that failed needs attention: the scan exits 2, as for a quarantine."""
    paths = make_box(tmp_path)
    seen: list[bool] = []
    outcome = AutofixOutcome(ok, None if ok else "build", "x", ())
    monkeypatch.setattr(security_actions, "_scan_targets_cmd", lambda args, p: 0)
    monkeypatch.setattr(security_actions, "run_urgent_queue",
                        lambda p, now: seen.append(_holds_fleet_lock(p)) or [outcome])
    assert security_actions.cmd_security_scan([], paths) == rc
    assert seen == [True]


@pytest.mark.parametrize("fails", [False, True])
def test_every_kev_watch_tick_runs_the_queue_under_its_lock(tmp_path, monkeypatch,
                                                            fails) -> None:
    paths = make_box(tmp_path)
    seen: list[bool] = []

    def watch(p, now):
        if fails:
            raise RuntimeError("refresh failed")
        return kev_watch.WatchResult()

    monkeypatch.setattr(kev_watch, "_watch", watch)
    monkeypatch.setattr(kev_watch, "run_urgent_queue",
                        lambda p, now: seen.append(_holds_fleet_lock(p)) or [])
    if fails:
        with pytest.raises(RuntimeError, match="refresh failed"):
            kev_watch.run_kev_watch(paths, _now())
    else:
        kev_watch.run_kev_watch(paths, _now())
    assert seen == [True]
