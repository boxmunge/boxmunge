# SPDX-License-Identifier: Apache-2.0
"""The urgent autofix flow through the real scan, quarantine and alerting
code (CVE autofix flowcharts, chart 1, tables A and B). Trivy, the image
probe, the Docker primitives and the patch runner itself are stubbed."""
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from boxmunge.commands.autofix_urgent_scan import PATCHING_NOTE
from boxmunge.commands import (
    autofix_queue_cmd, autofix_urgent, autofix_urgent_scan, kev_watch, quarantine_lift,
    security_actions, security_scan_core,
)
from boxmunge.cve import autofix_build, autofix_run
from boxmunge.cve.alerting import PERSISTENCE_CAVEAT
from boxmunge.cve.autofix_build import NotPatchable, Patchable
from boxmunge.cve.autofix_policy import AUTOFIX_URGENT_BUDGET
from boxmunge.cve.autofix_record import (
    AutofixJournal, PackageChange, PatchRecord, read_autofixing, read_journal,
    read_queue_entry, write_journal,
)
from boxmunge.cve.autofix_run import AutofixOutcome
from boxmunge.cve.exploited import ExploitedIndex, ExploitedSource
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.kev_watch_state import WatchState, write_watch
from boxmunge.cve.quarantine import QuarantineError, is_quarantined
from boxmunge.fileutil import project_lock
from boxmunge.image_pins import ImagePin, pin_ref
from boxmunge.state import StateError
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, render_site, scan_and_send, scan_result,
    seed_quarantine,
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
        self.dark: list[bool] = []

    def __call__(self, paths, project, findings, *, trigger, deadline, quarantined_for_patch):
        autofix_run._require_lock_held(paths, project)
        self.dark.append(quarantined_for_patch)
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
    # One alert at detection: the QUARANTINED alert itself when the project is
    # taken down for the patch, the started notice when it stays up.
    if dark:
        assert box.sent("patching") == []
        [quarantined] = box.sent("QUARANTINED")
        assert quarantined[1].endswith(PATCHING_NOTE)
    else:
        [started] = box.sent("patching")
        assert started[0].endswith(f"[boxmunge:demo] {CVE} found on demo, patching (site up)")
        assert started[2] == 0
        assert box.sent("QUARANTINED") == []

    start = _now()
    [outcome] = box.run()
    assert outcome.ok
    assert outcome.detected_at == entry.detected_at and start <= outcome.started_at <= _now()
    [(project, cves, trigger, deadline)] = box.runner.calls
    assert (project, cves, trigger) == ("demo", (CVE,), "urgent")
    assert deadline == outcome.started_at + AUTOFIX_URGENT_BUDGET
    assert box.runner.dark == [dark]   # only a dark patch may start it quarantined
    assert not is_quarantined("demo", paths)
    assert read_queue_entry(paths, "demo") is None and read_autofixing(paths, "demo") is None
    [patched] = box.sent("Autofix patched")
    assert patched[2] == 0
    assert ("quarantine is lifted" in patched[1]) is dark
    assert "Found " in patched[1] and ", patched " in patched[1]
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
    assert "Found " in body and ", failed " in body
    assert "mixed" not in body
    assert read_queue_entry(box.paths, "demo") is None
    assert read_autofixing(box.paths, "demo") is None


def test_urgent_nothing_to_patch_still_alerts_as_a_failure(tmp_path, monkeypatch) -> None:
    """Only the nightly digest lists a CVE gone from the images as fixed: the
    urgent flow alerts it as the failure it is there (table B applies)."""
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    box.runner.outcome = AutofixOutcome(False, "scan", "no image production runs carries it",
                                        (), nothing_to_patch=True)
    box.run()
    [failed] = box.sent("Autofix FAILED")
    assert failed[2] == 1 and "at the scan step" in failed[0]
    assert is_quarantined("demo", box.paths)


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


def test_a_project_waiting_its_turn_still_gets_its_whole_budget(tmp_path,
                                                               monkeypatch) -> None:
    """The budget runs from the attempt's own start: a long wait in the queue
    (many projects on one base image) does not turn a patch into downtime."""
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    detected = read_queue_entry(box.paths, "demo").detected_at
    later = _now() + AUTOFIX_URGENT_BUDGET + timedelta(minutes=5)
    assert not is_quarantined("demo", box.paths)   # waiting: up and marked
    [outcome] = box.run(later)
    [(_, _, _, deadline)] = box.runner.calls
    assert outcome.ok and outcome.started_at >= later
    assert deadline == outcome.started_at + AUTOFIX_URGENT_BUDGET
    assert not is_quarantined("demo", box.paths)
    [patched] = box.sent("Autofix patched")
    assert "Found " in patched[1] and f"{detected:%H:%M} UTC, patch started" in patched[1]


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
    box.paths.log_file.parent.mkdir(parents=True, exist_ok=True)
    box.scan("blog")
    box.scan("shop")
    bad = box.paths.project_autofix_queue("blog")
    bad.write_text("{not json")
    [outcome] = box.run()
    assert outcome.ok and [c[0] for c in box.runner.calls] == ["shop"]
    box.run()   # logged again, alerted once a day
    [problem] = box.sent("could not run")
    assert problem[2] == 1 and str(bad) in problem[1]
    assert box.paths.log_file.read_text().count("urgent autofix of blog could not run") == 2


def test_a_run_for_some_projects_leaves_the_others_queued(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed", projects=("blog", "shop"))
    box.scan("blog")
    box.scan("shop")
    [outcome] = autofix_urgent.run_urgent_queue(box.paths, _now(), only=["shop"])
    assert outcome.ok and [c[0] for c in box.runner.calls] == ["shop"]
    assert read_queue_entry(box.paths, "blog") is not None


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


def test_the_fleet_quarantine_alert_says_it_is_for_the_patch(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=9.8)
    _fleet(box)
    [quarantined] = box.sent("QUARANTINED")
    assert quarantined[1].endswith(PATCHING_NOTE) and box.sent("patching") == []


def test_the_fleet_quarantine_alert_carries_why_autofix_cannot_help(tmp_path,
                                                                    monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced")
    box.patchability = NotPatchable("no shell or package manager in the image")
    _fleet(box)
    [quarantined] = box.sent("QUARANTINED")
    assert "no shell or package manager in the image" in quarantined[1]


@pytest.mark.parametrize(("ok", "rc"), [(True, 0), (False, 2)])
def test_the_fleet_scan_hands_the_queue_on_under_its_lock(tmp_path, monkeypatch, ok,
                                                          rc) -> None:
    """A patch run here that failed needs attention: exit 2, as for a quarantine."""
    paths = make_box(tmp_path)
    seen: list = []
    outcome = AutofixOutcome(ok, None if ok else "build", "x", ())
    monkeypatch.setattr(security_actions, "_scan_targets_cmd", lambda args, p: 0)
    monkeypatch.setattr(security_actions, "after_scan",
                        lambda p, only=None: seen.append(only) or [outcome])
    assert security_actions.cmd_security_scan([], paths) == rc
    assert seen == [None]


def test_a_single_project_scan_hands_on_that_projects_patch(tmp_path, monkeypatch) -> None:
    paths = make_box(tmp_path)
    seen: list = []
    monkeypatch.setattr(security_actions, "_scan_targets_cmd", lambda args, p: 0)
    monkeypatch.setattr(security_actions, "after_scan",
                        lambda p, only=None: seen.append(only) or [])
    assert security_actions.cmd_security_scan(["demo"], paths) == 0
    assert seen == [["demo"]]


@pytest.mark.parametrize("fails", [False, True])
def test_every_kev_watch_tick_hands_the_queue_on(tmp_path, monkeypatch, fails) -> None:
    paths = make_box(tmp_path)
    seen: list = []

    def watch(p, now):
        if fails:
            raise RuntimeError("refresh failed")
        return kev_watch.WatchResult()

    monkeypatch.setattr(kev_watch, "_watch", watch)
    monkeypatch.setattr(kev_watch, "after_scan", lambda p, only=None: seen.append(only) or [])
    if fails:
        with pytest.raises(RuntimeError, match="refresh failed"):
            kev_watch.run_kev_watch(paths, _now())
    else:
        kev_watch.run_kev_watch(paths, _now())
    assert seen == [None]


class Systemctl:
    def __init__(self, monkeypatch, returncode: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode
        monkeypatch.setattr(autofix_queue_cmd.subprocess, "run", self._run)

    def _run(self, argv, **kw):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode, "", "unit not found")


@pytest.mark.parametrize("root", [True, False])
def test_root_starts_the_unit_and_deploy_runs_its_own_patch(tmp_path, monkeypatch,
                                                            root) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed", projects=("blog", "shop"))
    box.scan("blog")
    box.scan("shop")
    systemctl = Systemctl(monkeypatch)
    monkeypatch.setattr(autofix_queue_cmd, "_is_root", lambda: root)
    outcomes = autofix_queue_cmd.after_scan(box.paths, only=["shop"])
    if root:
        assert outcomes == [] and box.runner.calls == []
        assert systemctl.calls == [["systemctl", "start", "--no-block",
                                    "boxmunge-autofix.service"]]
    else:
        assert [o.ok for o in outcomes] == [True] and systemctl.calls == []
        assert [c[0] for c in box.runner.calls] == ["shop"]
        assert read_queue_entry(box.paths, "blog") is not None


def test_the_unit_is_not_started_for_an_empty_queue(tmp_path, monkeypatch) -> None:
    paths = make_box(tmp_path)
    systemctl = Systemctl(monkeypatch)
    monkeypatch.setattr(autofix_queue_cmd, "_is_root", lambda: True)
    autofix_queue_cmd.after_scan(paths)
    assert systemctl.calls == []


def test_a_unit_that_will_not_start_is_logged_loudly(tmp_path, monkeypatch, capsys) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed")
    box.scan()
    Systemctl(monkeypatch, returncode=5)
    autofix_queue_cmd.start_autofix_unit(box.paths)
    assert "could not start boxmunge-autofix.service" in capsys.readouterr().err
    assert read_queue_entry(box.paths, "demo") is not None


def test_the_autofix_command_goes_round_until_the_queue_is_empty(tmp_path,
                                                                 monkeypatch) -> None:
    """A patch queued while the unit runs is picked up by the same run."""
    box = _box(tmp_path, monkeypatch, "relaxed", projects=("blog", "shop"))
    box.scan("blog")
    monkeypatch.setattr(autofix_queue_cmd, "_is_root", lambda: True)
    real = box.runner.__call__

    def runner(paths, project, findings, **kw):
        if project == "blog":
            box.scan("shop")   # queued meanwhile, by another scan
        return real(paths, project, findings, **kw)

    monkeypatch.setattr(autofix_urgent, "autofix_project_locked", runner)
    assert autofix_queue_cmd.cmd_autofix_queue([], box.paths) == 0
    assert [c[0] for c in box.runner.calls] == ["blog", "shop"]


def test_the_autofix_command_is_root_only(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(autofix_queue_cmd, "_is_root", lambda: False)
    assert autofix_queue_cmd.cmd_autofix_queue([], make_box(tmp_path)) == 1
    assert "runs as root" in capsys.readouterr().err


def test_deploy_shell_refuses_the_autofix_queue(capsys) -> None:
    from boxmunge.shell import run_command
    assert run_command("security", ["autofix-queue"]) == 1
    assert "operator-only" in capsys.readouterr().err


def test_a_real_kev_watch_rescan_feeds_the_queue(tmp_path, monkeypatch) -> None:
    """The watch's own diff and rescan (scan_projects, the real scan) queue the
    newly listed CVE; only the hand-on to the unit is stubbed."""
    box = _box(tmp_path, monkeypatch, "balanced", listed=frozenset(), cvss=7.5)
    box.scan()                                   # stored: the finding, not yet listed
    assert read_queue_entry(box.paths, "demo") is None
    write_watch(box.paths, WatchState(_now() - timedelta(minutes=30), frozenset()))
    box.listed = CISA
    now = _now()
    kev = KevCatalog(frozenset({CVE}), now, now, "t")
    monkeypatch.setattr(kev_watch, "refresh_kev_and_alert", lambda p, n, **kw: kev)
    monkeypatch.setattr(kev_watch, "load_exploited", lambda p, today, cisa=None:
                        ExploitedIndex({CVE: CISA}, {}))
    handed: list = []
    monkeypatch.setattr(kev_watch, "after_scan", lambda p, only=None: handed.append(only))
    result = kev_watch.run_kev_watch(box.paths, now)
    assert result.rescanned == ("demo",) and handed == [None]
    entry = read_queue_entry(box.paths, "demo")
    assert entry.cves == (CVE,) and entry.downtime is False
    assert not is_quarantined("demo", box.paths)


# ---------- fix round 1 ----------


def test_a_cleanup_failure_after_a_patch_keeps_the_lift_and_the_notice(tmp_path,
                                                                       monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=9.8)
    box.scan()
    assert is_quarantined("demo", box.paths)

    def broken(paths, project):
        raise StateError("cannot remove the autofixing marker: read-only file system")

    monkeypatch.setattr(autofix_urgent, "clear_autofixing", broken)
    [outcome] = box.run()
    assert outcome.ok and not is_quarantined("demo", box.paths)
    [patched] = box.sent("Autofix patched")
    assert "Nothing was patched" not in patched[1] and "read-only file system" in patched[1]
    assert box.sent("could not run") == []


def test_a_lift_that_fails_keeps_the_patch_queued(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=9.8)
    box.scan()

    def refused(paths, project, *, component):
        raise QuarantineError("Caddy reload failed")

    monkeypatch.setattr(autofix_urgent, "restore_from_quarantine", refused)
    box.run()
    assert is_quarantined("demo", box.paths)
    assert read_queue_entry(box.paths, "demo") is not None
    [patched] = box.sent("Autofix patched")
    assert patched[2] == 1 and "could not be lifted: Caddy reload failed" in patched[1]
    assert "stays queued" in patched[1]


def test_a_quarantine_for_another_cve_is_reasserted_after_the_patch(tmp_path,
                                                                    monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=9.8)
    box.scan()
    record = json.loads(box.paths.project_quarantine_state("demo").read_text())
    box.paths.project_quarantine_state("demo").write_text(
        json.dumps({**record, "cve_id": "CVE-2026-0099"}))
    stops = box.docker.calls.count("compose_stop")
    [outcome] = box.run()
    assert outcome.ok and is_quarantined("demo", box.paths)
    assert box.docker.calls.count("compose_stop") == stops + 1
    [patched] = box.sent("Autofix patched")
    assert "stays quarantined for CVE-2026-0099" in patched[1]


def test_autofix_turned_off_before_the_run_applies_the_fallback(tmp_path,
                                                                monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    manifest = box.paths.project_manifest("demo")
    doc = yaml.safe_load(manifest.read_text())
    doc["security"]["autofix"] = False
    manifest.write_text(yaml.safe_dump(doc))
    [outcome] = box.run()
    assert not outcome.ok and box.runner.calls == []
    assert is_quarantined("demo", box.paths)
    [failed] = box.sent("Autofix FAILED")
    assert "turned off" in failed[1] and "quarantined now" in failed[1]


def test_strict_overdue_fix_is_patched_dark_through_the_scan(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "strict", listed=frozenset())
    t0 = _now() - timedelta(days=8)
    monkeypatch.setattr(security_scan_core, "_now", lambda: t0)
    box.scan()                                    # first seen: the grace starts
    assert read_queue_entry(box.paths, "demo") is None
    monkeypatch.setattr(security_scan_core, "_now", lambda: t0 + timedelta(days=7))
    box.scan()                                    # overdue: quarantined, patched at once
    assert is_quarantined("demo", box.paths)
    assert read_queue_entry(box.paths, "demo").downtime is True
    [quarantined] = box.sent("QUARANTINED")
    assert quarantined[1].endswith(PATCHING_NOTE)
    [outcome] = box.run()
    assert outcome.ok and not is_quarantined("demo", box.paths)


def test_a_breaker_held_quarantine_is_patched_up_and_its_fallback_stays_held(
        tmp_path, monkeypatch) -> None:
    """Enough paranoid projects hit by one non-KEV CVE trip the breaker: none
    goes dark, each is patched with the site up and says so; a failed patch
    leaves the quarantine to the operator."""
    box = _box(tmp_path, monkeypatch, "paranoid", listed=frozenset(),
               projects=("blog", "shop", "wiki"))
    now = _now()
    run = security_actions.scan_projects(box.paths, ["blog", "shop", "wiki"],
                                         kev=KevCatalog(frozenset(), now, now, "t"))
    assert sorted(run.held) == ["blog", "shop", "wiki"]
    for project in run.held:
        assert not is_quarantined(project, box.paths)
        assert read_queue_entry(box.paths, project).downtime is False
        assert read_autofixing(box.paths, project).downtime is False
    started = box.sent("patching (site up)")
    assert len(started) == 3 and box.sent("QUARANTINED") == []
    box.runner.outcome = AutofixOutcome(False, "build", "mirror down", ())
    box.run()
    assert not any(is_quarantined(p, box.paths) for p in run.held)
    failed = box.sent("Autofix FAILED")
    assert len(failed) == 3 and all("circuit breaker holds" in f[1] for f in failed)


def test_a_reused_entry_follows_the_projects_real_state(tmp_path, monkeypatch) -> None:
    """Queued up; quarantined since (a failed lift, an operator): the next
    scan rewrites the entry dark, keeping its detection time."""
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    first = read_queue_entry(box.paths, "demo")
    seed_quarantine(box.paths, cve_id=CVE)
    box.scan()
    entry = read_queue_entry(box.paths, "demo")
    assert entry.downtime is True and entry.detected_at == first.detected_at
    assert read_autofixing(box.paths, "demo").downtime is True


def test_a_killed_run_is_rolled_back_then_the_patch_carries_on(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    patched = "sha256:" + "e" * 64
    built = ImagePin("web", pin_ref("demo", "web", patched), patched, "autofix")
    write_journal(box.paths, "demo", AutofixJournal(_now(), (), (), (built,)))
    undone: list = []   # the runner's own Docker seams (tests/cve/test_autofix_run.py)
    monkeypatch.setattr(autofix_run, "clear_pins", lambda p, project: undone.append("pins"))
    monkeypatch.setattr(autofix_run, "recreate_project",
                        lambda p, project, files, component, patch_cves:
                        undone.append("recreate"))
    monkeypatch.setattr(autofix_run, "wait_healthy", lambda *a, **k: (True, []))
    monkeypatch.setattr(autofix_run, "remove_patched", lambda pin: undone.append(pin.ref))
    [outcome] = box.run()
    assert undone == ["pins", "recreate", built.ref]
    assert read_journal(box.paths, "demo") is None
    [interrupted] = box.sent("interrupted")
    assert interrupted[2] == 1 and "has been rolled back" in interrupted[1]
    assert "quarantined now" in interrupted[1]        # table B for the queued finding
    assert outcome.ok and not is_quarantined("demo", box.paths)   # then patched, lifted


def test_the_real_probe_decides_queueing(tmp_path, monkeypatch) -> None:
    """Without the unit-tier probe stub: the probe's own docker calls are
    faked, and an apt image is queued."""
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    monkeypatch.setattr(autofix_urgent_scan, "probe", autofix_build.probe)
    monkeypatch.setattr(autofix_build, "_image_doc", lambda ref: {"Config": {"User": ""}})
    ran: list = []
    monkeypatch.setattr(autofix_build, "_run", lambda argv, **kw: ran.append(argv) or
                        subprocess.CompletedProcess(argv, 0, "apt\n", ""))
    box.scan()
    assert read_queue_entry(box.paths, "demo") is not None
    assert ran and ran[0][:2] == ["docker", "run"]


# ---------- fix round 2 ----------


def test_a_stale_entry_that_cannot_be_dropped_does_not_stall_the_queue(tmp_path,
                                                                     monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "relaxed", projects=("blog", "shop"))
    box.scan("blog")
    box.scan("shop")
    box.found = []
    box.scan("blog")                       # blog's finding is gone: its entry is stale
    box.found = [replace(finding(CVE, fix="2"), cvss_score=9.8)]
    real = autofix_urgent.remove_queue_entry

    def stuck(paths, project):
        if project == "blog":
            raise StateError("cannot remove the autofix queue entry: read-only file system")
        real(paths, project)

    monkeypatch.setattr(autofix_urgent, "remove_queue_entry", stuck)
    [outcome] = box.run()
    assert outcome.ok and [c[0] for c in box.runner.calls] == ["shop"]


def test_an_interrupted_run_with_an_unreadable_entry_says_so(tmp_path, monkeypatch) -> None:
    box = _box(tmp_path, monkeypatch, "balanced", cvss=7.5)
    box.scan()
    box.paths.project_autofix_queue("demo").write_text("{not json")
    patched = "sha256:" + "e" * 64
    built = ImagePin("web", pin_ref("demo", "web", patched), patched, "autofix")
    write_journal(box.paths, "demo", AutofixJournal(_now(), (), (), (built,)))
    for name, fake in [("clear_pins", lambda p, project: None),
                       ("recreate_project", lambda p, project, files, component: None),
                       ("wait_healthy", lambda *a, **k: (True, [])),
                       ("remove_patched", lambda pin: None)]:
        monkeypatch.setattr(autofix_run, name, fake)
    assert box.run() == []
    [interrupted] = box.sent("interrupted")
    assert "cannot be read" in interrupted[1] and "no fallback was applied" in interrupted[1]
    assert "queued any more" not in interrupted[1]
