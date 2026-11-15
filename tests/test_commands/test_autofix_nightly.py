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
from boxmunge.cve.autofix_policy import AUTOFIX_NIGHTLY_BUDGET
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
        monkeypatch.setattr(container_update_cmd, "update_target_locked", self._update)

    def _update(self, paths, target):
        if target.is_caddy:
            return {"name": target.name, "status": "no_change"}
        return {"name": target.name, "status": self.update_status, "reason": "pull_failed: x"}

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
        assert autofix_nightly.run_nightly_autofix(box.paths, "demo") is None
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


def test_failed_container_update_skips_nightly(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    box.update_status = "failed"
    box.paths.log_file.parent.mkdir(parents=True, exist_ok=True)
    box.update()
    assert box.runner.calls == []
    assert box.digests() == []
    assert ("demo: nightly autofix skipped: tonight's container update failed "
            "(pull_failed: x)") in box.paths.log_file.read_text()


def test_monitor_stopped_project_skipped(tmp_path, monkeypatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.scan()
    monkeypatch.setattr(autofix_nightly, "is_monitor_stopped", lambda project, paths: True)
    with project_lock("demo", box.paths):
        assert autofix_nightly.run_nightly_autofix(box.paths, "demo") is None
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


def test_budget_is_thirty_minutes() -> None:
    assert AUTOFIX_NIGHTLY_BUDGET == timedelta(minutes=30)
