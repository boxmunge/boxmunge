# SPDX-License-Identifier: Apache-2.0
"""The nightly autofix flow: container-update patches the fixable findings
tonight's scan stored, under each project's lock, and sends one quiet
digest (CVE autofix design, "Non-KEV flow"). The scan is the real one;
Trivy, the Docker primitives, the container update itself and the patch
runner are stubbed."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from boxmunge.commands import autofix_nightly, container_update_cmd, security_scan_core
from boxmunge.cve import autofix_run
from boxmunge.cve.autofix_policy import AUTOFIX_NIGHTLY_BUDGET, NIGHTLY_AUTOFIX_WINDOW
from boxmunge.cve.autofix_record import (
    AutofixJournal, PackageChange, PatchRecord, QueuedFinding, QueueEntry, write_journal,
    write_queue_entry,
)
from boxmunge.cve.autofix_run import AutofixOutcome
from boxmunge.cve.exploited import ExploitedIndex, ExploitedSource
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.scanner import Severity
from boxmunge.fileutil import project_lock
from tests.test_commands.cve_helpers import (
    Docker, Pushover, finding, make_box, scan_and_send, scan_result, seed_quarantine,
)

CVE = "CVE-2026-0001"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Runner:
    """Stands in for autofix_run.autofix_project_locked."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...], str, datetime]] = []
        self.outcome: AutofixOutcome | None = None
        self.raises: Exception | None = None

    def __call__(self, paths, project, findings, *, trigger, deadline):
        autofix_run._require_lock_held(paths, project)
        self.calls.append((project, tuple(sorted({fd.finding.cve_id for fd in findings})),
                           trigger, deadline))
        if self.raises is not None:
            raise self.raises
        if self.outcome is not None:
            return self.outcome
        record = PatchRecord(
            project=project, service="web", base_ref=f"{project}-web:1",
            base_digest="sha256:" + "b" * 64,
            patched_ref=f"boxmunge.invalid/{project}/web:autofix-aaaaaaaaaaaa",
            patched_image_id="sha256:" + "a" * 64,
            packages=(PackageChange("openssl", "1", "2"), PackageChange("libssl3", "1", "2")),
            cves=(CVE,), created_at=_now(), trigger="nightly")
        return AutofixOutcome(True, None, "patched web", (record,))


class Box:
    def __init__(self, tmp_path, monkeypatch, posture: str = "balanced", *,
                 sev: Severity = Severity.HIGH, listed=frozenset(),
                 projects=("demo",)) -> None:
        self.paths = make_box(tmp_path, projects=projects, security={"posture": posture})
        self.found = [replace(finding(CVE, fix="2", sev=sev), cvss_score=7.5)]
        self.listed = listed
        monkeypatch.setattr(security_scan_core, "scan_image",
                            lambda ref, timeout: scan_result(ref, self.found))
        monkeypatch.setattr(security_scan_core, "load_exploited", lambda p, today, cisa=None:
                            ExploitedIndex({CVE: self.listed} if self.listed else {}, {}))
        self.docker = Docker(monkeypatch)
        self.pushover = Pushover(monkeypatch, self.paths)
        self.runner = Runner()
        monkeypatch.setattr(autofix_nightly, "autofix_project_locked", self.runner)
        self.update_status = "no_change"
        self.update_result: dict = {"reason": "pull_failed: x"}
        self.updated: list[str] = []
        monkeypatch.setattr(container_update_cmd, "update_target_locked", self._update)

    def _update(self, paths, target):
        self.updated.append(target.name)
        if target.is_caddy:
            return {"name": target.name, "status": "no_change"}
        return {"name": target.name, "status": self.update_status, "tags_not_restored": [],
                "rollback_attempted": False, "rollback_succeeded": None,
                **self.update_result}

    def scan(self, project: str = "demo") -> None:
        now = _now()
        scan_and_send(self.paths, project, kev=KevCatalog(frozenset(), now, now, "t"))
        self.pushover.clear()

    def update(self, **kw) -> int:
        return container_update_cmd.run_container_update(self.paths, **kw)

    def digests(self) -> list[tuple[str, str, int]]:
        return [s for s in self.pushover.sent if "] Nightly autofix:" in s[0]]


def test_eligible_findings_patched_and_digested(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    before = _now()
    assert box.update() == 0
    [(project, cves, trigger, deadline)] = box.runner.calls
    assert (project, cves, trigger) == ("demo", (CVE,), "nightly")
    assert before + AUTOFIX_NIGHTLY_BUDGET <= deadline <= _now() + AUTOFIX_NIGHTLY_BUDGET
    [(title, body, priority)] = box.pushover.sent
    assert priority == -1
    assert title == "[box.example.com] Nightly autofix: 1 project patched"
    assert f"patched: demo: {CVE} (2 packages)" in body


def test_probation_skips_nightly_autofix(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.paths.upgrade_state.mkdir(parents=True, exist_ok=True)
    box.paths.probation.write_text('{"version": "0.12.0"}')
    assert box.update() == 0                 # the whole run waits for probation
    assert box.update(force=True) == 0       # a forced update still never autofixes
    assert box.runner.calls == []
    assert box.pushover.sent == []


def test_quarantined_project_skipped(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, projects=("demo", "shop"))
    box.scan("demo")
    box.scan("shop")
    seed_quarantine(box.paths, "demo")
    box.update()
    assert [c[0] for c in box.runner.calls] == ["shop"]
    # The flow's own gate holds too, whoever calls it.
    with project_lock("demo", box.paths):
        assert autofix_nightly.run_nightly_autofix(
            box.paths, "demo", until=autofix_nightly.window_end()) is None
    assert [c[0] for c in box.runner.calls] == ["shop"]


def test_failure_goes_to_digest_with_reason(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.runner.outcome = AutofixOutcome(False, "build", "apt-get exited 100", ())
    box.update()
    [(title, body, priority)] = box.pushover.sent
    assert priority == -1
    assert title == "[box.example.com] Nightly autofix: 1 project could not be patched"
    assert "could not patch: demo: build: apt-get exited 100" in body


def test_failure_with_rollback_problems_is_urgent(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.runner.outcome = AutofixOutcome(False, "health", "web unhealthy", (),
                                        ("rollback could not restore the pins",))
    box.update()
    [(title, body, priority)] = box.pushover.sent
    assert priority == 1
    assert "Autofix FAILED at the health step" in title and CVE in title
    assert "rollback could not restore the pins" in body
    assert box.digests() == []


def test_unexpected_runner_error_is_a_failure(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    error = RuntimeError("boom")
    error.add_note("rollback could not recreate the previous containers")
    box.runner.raises = error
    box.update()
    [(title, body, priority)] = box.pushover.sent
    assert priority == 1 and "boom" in body
    assert "rollback could not recreate the previous containers" in body


@pytest.mark.parametrize(("sev", "patched"), [
    pytest.param(Severity.HIGH, True, id="high-patched"),
    pytest.param(Severity.MEDIUM, False, id="medium-not-patched"),
])
def test_relaxed_project_patched_by_balanced_threshold(tmp_path, monkeypatch, sev,
                                                       patched) -> None:
    box = Box(tmp_path, monkeypatch, "relaxed", sev=sev)
    box.scan()
    box.update()
    assert bool(box.runner.calls) is patched
    assert bool(box.digests()) is patched


def test_strict_patches_what_it_alerts_on(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, "strict", sev=Severity.MEDIUM)
    box.scan()
    box.update()
    assert [c[0] for c in box.runner.calls] == ["demo"]


def test_urgent_and_paranoid_findings_left_to_the_urgent_flow(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, "paranoid")
    box.scan()
    # The scan queued it for the autofix unit; nightly leaves the project alone.
    box.update()
    assert box.runner.calls == []


def test_known_exploited_finding_not_patched_nightly(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, listed=frozenset({ExploitedSource.CISA}))
    box.scan()
    # As if the autofix unit had run it and given up: still nothing for tonight.
    box.paths.project_autofix_queue("demo").unlink(missing_ok=True)
    box.update()
    assert box.runner.calls == []


def test_queued_urgent_patch_skips_nightly(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    write_queue_entry(box.paths, "demo", QueueEntry(
        _now(), (QueuedFinding(CVE, "openssl", "demo-web:1"),), False))
    box.update()
    assert box.runner.calls == []


def test_leftover_journal_skips_nightly(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    write_journal(box.paths, "demo", AutofixJournal(_now(), (), (), ()))
    box.update()
    assert box.runner.calls == []


def test_autofix_off_skips_nightly(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    manifest = box.paths.project_manifest("demo")
    doc = yaml.safe_load(manifest.read_text())
    doc["security"]["autofix"] = False
    manifest.write_text(yaml.safe_dump(doc))
    box.scan()
    box.update()
    assert box.runner.calls == []


@pytest.mark.parametrize("result", [
    pytest.param({"reason": "pull_failed: registry down"}, id="pull-failed"),
    pytest.param({"reason": "backup_failed"}, id="backup-failed"),
    pytest.param({"reason": "unhealthy: web", "rollback_attempted": True,
                  "rollback_succeeded": True}, id="rolled-back-healthy"),
])
def test_failed_update_on_previous_images_still_patches(tmp_path, monkeypatch,
                                                        result) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.update_status, box.update_result = "failed", result
    box.update()
    assert [c[0] for c in box.runner.calls] == ["demo"]


@pytest.mark.parametrize(("result", "why"), [
    pytest.param({"reason": "unhealthy: web"}, "unhealthy: web", id="left-broken"),
    pytest.param({"reason": "recreate_failed: x", "rollback_attempted": True,
                  "rollback_succeeded": False}, "recreate_failed: x", id="rollback-failed"),
    pytest.param({"reason": "pull_failed: x; tag_restore_failed: web:1",
                  "tags_not_restored": ["web:1"]}, "pull_failed: x; tag_restore_failed: web:1",
                 id="tags-not-restored"),
    pytest.param({"reason": "exception: boom"}, "exception: boom", id="unknown-state"),
])
def test_failed_update_that_left_the_project_changed_skips(tmp_path, monkeypatch, result,
                                                           why) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.update_status, box.update_result = "failed", result
    box.paths.log_file.parent.mkdir(parents=True, exist_ok=True)
    box.update()
    assert box.runner.calls == []
    [(title, body, priority)] = box.digests()
    assert priority == -1 and title.endswith("Nightly autofix: 1 project skipped")
    assert f"skipped: demo: container update failed: {why}" in body
    assert "demo: nightly autofix skipped: container update failed" in \
        box.paths.log_file.read_text()


def test_failed_update_with_nothing_to_patch_sends_nothing(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, sev=Severity.LOW)
    box.scan()
    box.update_status, box.update_result = "failed", {"reason": "unhealthy: web"}
    box.update()
    assert box.digests() == []


def test_project_with_container_updates_off_still_patched(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, projects=("blog", "shop"))
    manifest = box.paths.project_manifest("blog")
    doc = yaml.safe_load(manifest.read_text())
    doc["container_updates"] = {"enabled": False}
    manifest.write_text(yaml.safe_dump(doc))
    box.scan("blog")
    box.scan("shop")
    box.update()
    assert "blog" not in box.updated
    assert sorted(c[0] for c in box.runner.calls) == ["blog", "shop"]
    [(title, _body, _p)] = box.digests()
    assert title.endswith("Nightly autofix: 2 projects patched")


def test_box_with_container_updates_off_still_patched(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    config = yaml.safe_load(box.paths.config_file.read_text())
    config["container_updates"] = {"enabled": False}
    box.paths.config_file.write_text(yaml.safe_dump(config))
    box.scan()
    assert box.update() == 0
    assert box.updated == []
    assert [c[0] for c in box.runner.calls] == ["demo"]
    assert len(box.digests()) == 1


def test_not_updated_project_keeps_its_gates(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    manifest = box.paths.project_manifest("demo")
    doc = yaml.safe_load(manifest.read_text())
    doc["container_updates"] = {"enabled": False}
    manifest.write_text(yaml.safe_dump(doc))
    box.scan()
    seed_quarantine(box.paths, "demo")
    box.update()
    assert box.runner.calls == []


def test_not_updated_project_busy_is_listed(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    config = yaml.safe_load(box.paths.config_file.read_text())
    config["container_updates"] = {"enabled": False}
    box.paths.config_file.write_text(yaml.safe_dump(config))
    box.scan()
    with project_lock("demo", box.paths):
        box.update()
    assert box.runner.calls == []
    [(_t, body, _p)] = box.digests()
    assert "skipped: demo: another operation holds the project" in body


@pytest.mark.parametrize(("status", "line"), [
    pytest.param("succeeded", f"fixed by tonight's update: demo: {CVE}", id="updated"),
    pytest.param("no_change", f"no longer in the running images: demo: {CVE}", id="unchanged"),
])
def test_cve_gone_from_the_running_images_is_not_a_failure(tmp_path, monkeypatch, status,
                                                           line) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.update_status = status
    box.runner.outcome = AutofixOutcome(False, "scan", "no image production runs carries it",
                                        (), nothing_to_patch=True)
    box.update()
    [(title, body, priority)] = box.digests()
    assert priority == -1 and line in body and "could not patch" not in body
    assert "could not" not in title


def test_patches_stop_starting_near_the_window_end(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, projects=("blog", "shop"))
    box.scan("blog")
    box.scan("shop")
    clock = [_now()]
    monkeypatch.setattr(autofix_nightly, "_now", lambda: clock[0])
    real = box.runner.__call__

    def slow(paths, project, findings, *, trigger, deadline):
        clock[0] += timedelta(hours=2, minutes=21)   # 39 minutes left: under 30 + 10
        return real(paths, project, findings, trigger=trigger, deadline=deadline)

    monkeypatch.setattr(autofix_nightly, "autofix_project_locked", slow)
    box.update()
    assert [c[0] for c in box.runner.calls] == ["blog"]
    [(title, body, priority)] = box.digests()
    assert title.endswith("Nightly autofix: 1 project patched, 1 deferred")
    assert "deferred to the next maintenance window: shop" in body


def test_window_leaves_room_for_a_whole_patch(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, projects=("blog", "shop"))
    box.scan("blog")
    box.scan("shop")
    clock = [_now()]
    monkeypatch.setattr(autofix_nightly, "_now", lambda: clock[0])
    real = box.runner.__call__

    def slow(paths, project, findings, *, trigger, deadline):
        clock[0] += timedelta(hours=2, minutes=20)   # exactly 40 minutes left
        return real(paths, project, findings, trigger=trigger, deadline=deadline)

    monkeypatch.setattr(autofix_nightly, "autofix_project_locked", slow)
    box.update()
    assert [c[0] for c in box.runner.calls] == ["blog", "shop"]


def test_monitor_stopped_project_skipped(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    monkeypatch.setattr(autofix_nightly, "is_monitor_stopped", lambda project, paths: True)
    with project_lock("demo", box.paths):
        assert autofix_nightly.run_nightly_autofix(
            box.paths, "demo", until=autofix_nightly.window_end()) is None
    assert box.runner.calls == []


def test_updated_project_patched_in_the_same_run(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.update_status = "succeeded"
    box.update()
    assert [c[0] for c in box.runner.calls] == ["demo"]


def test_dry_run_never_patches(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    monkeypatch.setattr(container_update_cmd, "_dry_run_target",
                        lambda paths, target: {"name": target.name, "status": "no_change"})
    box.update(dry_run=True)
    assert box.runner.calls == []


def test_digest_covers_every_project(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, projects=("blog", "shop"))
    box.scan("blog")
    box.scan("shop")
    outcomes = {"blog": AutofixOutcome(False, "probe", "no package manager", ())}
    real = box.runner.__call__

    def runner(paths, project, findings, *, trigger, deadline):
        if project in outcomes:
            box.runner.calls.append((project, (), trigger, deadline))
            return outcomes[project]
        return real(paths, project, findings, trigger=trigger, deadline=deadline)

    monkeypatch.setattr(autofix_nightly, "autofix_project_locked", runner)
    box.update()
    [(title, body, priority)] = box.pushover.sent
    assert priority == -1
    assert title == "[box.example.com] Nightly autofix: 1 project patched, 1 could not be patched"
    assert body.index("patched: shop") < body.index("could not patch: blog")


def test_no_stored_scan_runs_nothing(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.update()
    assert box.runner.calls == []
    assert box.pushover.sent == []


def test_unreadable_scan_state_goes_to_digest(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.paths.project_scan_state("demo").write_text("{not json")
    box.update()
    assert box.runner.calls == []
    [(title, body, priority)] = box.pushover.sent
    assert priority == -1 and "could not patch: demo:" in body
    assert "cannot be read" in body


def test_budget_and_window() -> None:
    assert AUTOFIX_NIGHTLY_BUDGET == timedelta(minutes=30)
    assert NIGHTLY_AUTOFIX_WINDOW == timedelta(hours=3)


def test_not_updated_project_busy_with_nothing_to_patch_is_not_listed(tmp_path,
                                                                     monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch, sev=Severity.LOW)
    config = yaml.safe_load(box.paths.config_file.read_text())
    config["container_updates"] = {"enabled": False}
    box.paths.config_file.write_text(yaml.safe_dump(config))
    box.scan()
    with project_lock("demo", box.paths):
        box.update()
    assert box.digests() == []
