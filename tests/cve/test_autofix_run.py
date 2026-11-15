# SPDX-License-Identifier: Apache-2.0
"""The autofix runner: scan, probe, build, scan, swap, health, record, and
an unconditional rollback on any failure.

Docker is faked at the runner's own seams (the deployed inventory, the
release-image scan, the builder, the pins, the recreate and the health
wait): one fake box keeps the containers (with their IDs), the images and
the pins, so each test can see exactly what a run changed. The patch
builder, the pins and the recreate have their own tests on real Docker.
"""
from __future__ import annotations

import itertools
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.commands.security_scan_core import ProjectScan
from boxmunge.commands.security_scan_inputs import ScanTarget
from boxmunge.cve import autofix_plan, autofix_run
from boxmunge.cve.autofix_build import NotPatchable, Patchable, PatchedImage
from boxmunge.cve.autofix_record import PackageChange, PatchRecord, read_records, write_records
from boxmunge.cve.autofix_run import autofix_project_locked
from boxmunge.cve.policy_types import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.scanner import PkgClass, Severity
from boxmunge.deployed_inventory import DeployedInventory, DeployedService
from boxmunge.docker_containers import ProjectContainer
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import project_lock
from boxmunge.image_pins import ImagePin, pin_ref
from tests.test_commands.cve_helpers import finding

NAME = "shop"
CVE = "CVE-2026-1111"
WEB, DB = "sha256:" + "a" * 64, "sha256:" + "d" * 64


def _fd(cve: str = CVE, *, pkg: str = "openssl", fix: str | None = "3.0.9",
        disposition: Disposition = Disposition.QUARANTINE,
        pkg_class: PkgClass = PkgClass.OS) -> FindingDisposition:
    f = replace(finding(cve, pkg=pkg, fix=fix), pkg_class=pkg_class)
    return FindingDisposition(f, Severity.CRITICAL, 0, Severity.CRITICAL, disposition, None, "")


class Box:
    """A fake production: {service: (container ID, image ID)}, the images a
    scan finds findings in, and the pins."""

    def __init__(self, monkeypatch) -> None:
        self.release = {"web": WEB, "db": DB}
        self.containers = {svc: (f"c-{svc}-0", img) for svc, img in self.release.items()}
        self.findings: dict[str, list[FindingDisposition]] = {WEB: [_fd()], DB: []}
        self.patched_findings: dict[str, list[FindingDisposition]] = {}
        self.pins: tuple[ImagePin, ...] = ()
        self.refs: dict[str, str] = {}
        self.built: list[tuple[str, str, dict]] = []
        self.removed: list[str] = []
        self.recreates = 0
        self.build_error: Exception | None = None
        self.unhealthy_on_patched = False
        self.probe_result: Patchable | NotPatchable = Patchable("apk", "")
        self.on_health = None
        self.scans = 0
        self.checked: list[dict] = []
        self.check_error: Exception | None = None
        self.scan_error: Exception | None = None
        self.log: list[tuple[str, str, dict]] = []
        self._ids = itertools.count(1)
        for name, fake in [("load_deployed_inventory", self._inventory),
                           ("scan_release_images", self._scan),
                           ("load_kev", lambda paths: None)]:
            monkeypatch.setattr(autofix_plan, name, fake)
        for name, fake in [("load_project_meta", lambda paths, project: object()),
                           ("probe", lambda ref: self.probe_result),
                           ("build_patched", self._build),
                           ("check_versions", self._check_versions),
                           ("remove_patched", lambda pin: self.removed.append(pin.ref)),
                           ("read_pins", lambda paths, project: self.pins),
                           ("write_pins", self._write_pins),
                           ("clear_pins", self._clear_pins),
                           ("recreate_project", self._recreate),
                           ("wait_healthy", self._wait_healthy),
                           ("log_operation", self._logger("op")),
                           ("log_error", self._logger("error"))]:
            monkeypatch.setattr(autofix_run, name, fake)

    def _logger(self, level):
        def log(component, message, paths, project=None, detail=None):
            self.log.append((level, message, detail or {}))
        return log

    def _inventory(self, project_dir, files, project):
        return DeployedInventory(project, {svc: DeployedService(
            svc, f"example/{svc}:1", False, True, (ProjectContainer(
                f"{project}-{svc}-1", svc, img, (), True, "healthy", False, None, "always"),))
            for svc, (_cid, img) in self.containers.items()})

    def _check_versions(self, image, patchability, packages):
        self.checked.append(dict(packages))
        if self.check_error is not None:
            raise self.check_error
        return dict(packages)

    def _scan(self, paths, target, meta, starts, unnamed, kev):
        self.scans += 1
        if self.scan_error is not None:
            raise self.scan_error
        decisions, targets, ids = [], [], {}
        for svc, start in starts.items():
            image = self.refs.get(start.scan_ref, start.scan_ref)
            found = self.findings[image] if image in self.findings \
                else self.patched_findings.get(svc, [])
            ids[svc] = image
            targets.append(ScanTarget(svc, image))
            decisions.append(ProjectDecision(NAME, image, tuple(found), False, False,
                                             datetime.now(timezone.utc)))
        return (ProjectScan(NAME, "balanced", False, tuple(decisions), ()), ids, targets, None)

    def _build(self, project, service, base, packages, patchability):
        if self.build_error is not None:
            raise self.build_error
        image_id = "sha256:" + f"{next(self._ids):x}".rjust(64, "e")
        ref = pin_ref(project, service, image_id)
        self.refs[ref] = image_id
        self.built.append((service, base, dict(packages)))
        return PatchedImage(ref, image_id, {p: "3.0.9-r0" for p in packages})

    def _write_pins(self, paths, project, pins):
        self.pins = tuple(sorted(pins, key=lambda p: p.service))

    def _clear_pins(self, paths, project):
        self.pins = ()

    def _recreate(self, paths, project, files, *, component, patch_cves=()):
        self.recreates += 1
        pinned = {p.service: p.image_id for p in self.pins}
        for svc, (cid, img) in list(self.containers.items()):
            want = pinned.get(svc, self.release[svc])
            if want != img:
                self.containers[svc] = (f"c-{svc}-{next(self._ids)}", want)

    def _wait_healthy(self, project, services, one_shots=frozenset()):
        if self.on_health is not None:
            self.on_health()
        bad = [svc for svc, (_c, img) in self.containers.items()
               if self.unhealthy_on_patched and img not in self.release.values()]
        return (not bad, bad)

    def running(self) -> dict[str, str]:
        return {svc: img for svc, (_c, img) in self.containers.items()}


@pytest.fixture
def box(monkeypatch) -> Box:
    return Box(monkeypatch)


def _run(paths, findings=None, *, deadline=None, trigger="urgent", dark=False):
    with project_lock(NAME, paths):
        return autofix_project_locked(
            paths, NAME, findings if findings is not None else [_fd()], trigger=trigger,
            deadline=deadline or datetime.now(timezone.utc) + timedelta(minutes=30),
            quarantined_for_patch=dark)


def test_success_writes_pins_and_records(paths, box) -> None:
    outcome = _run(paths)
    assert (outcome.ok, outcome.failed_step) == (True, None), outcome.reason
    (svc, base, packages), = box.built
    assert (svc, base, packages) == ("web", WEB, {"openssl": "3.0.9"})
    (pin,) = box.pins
    assert pin.service == "web" and box.running()["web"] == pin.image_id
    assert box.running()["db"] == DB
    (record,) = outcome.records
    assert (record.service, record.base_digest, record.patched_ref, record.cves,
            record.trigger) == ("web", WEB, pin.ref, (CVE,), "urgent")
    assert record.packages == (PackageChange("openssl", "1", "3.0.9-r0"),)
    assert read_records(paths, NAME) == outcome.records
    assert box.removed == []
    (start_level, start, start_detail), (level, done, detail) = box.log
    assert start_level == "op" and NAME in start and CVE in start
    assert start_detail["cves"] == [CVE]
    assert level == "op" and "web" in done and CVE in done
    assert (detail["services"], detail["step"], detail["cves"]) == (["web"], None, [CVE])


def test_build_failure_leaves_service_running(paths, box) -> None:
    """The distro mirror is unreachable: the build fails with the package
    manager's stderr tail, and the running containers are untouched."""
    box.build_error = DockerError(
        "Command failed (exit 1): docker build --no-cache -t x -\n"
        "WARNING: fetching https://dl-cdn.alpinelinux.org/alpine/v3.19/main: "
        "temporary error (try again later)")
    before = dict(box.containers)
    outcome = _run(paths)
    assert (outcome.ok, outcome.failed_step) == (False, "build")
    assert "temporary error (try again later)" in outcome.reason
    assert box.containers == before          # the same container IDs, same images
    assert box.recreates == 0 and box.pins == () and box.removed == []
    assert read_records(paths, NAME) == ()
    level, message, detail = box.log[-1]
    assert level == "error" and detail["step"] == "build" and detail["services"] == ["web"]
    assert "temporary error" in detail["reason"]


def test_health_failure_rolls_back_even_with_leave_broken(paths, box) -> None:
    """The runner never reads the container-update strategy: whatever it is
    (leave_broken is the default), a patch that fails its health check is
    rolled back, the previous pins restored exactly."""
    other = ImagePin("db", pin_ref(NAME, "db", "sha256:" + "f" * 64), "sha256:" + "f" * 64,
                     "autofix")
    box.pins = (other,)
    box.release["db"] = other.image_id   # db already runs its earlier patch
    box.containers["db"] = ("c-db-0", other.image_id)
    box.findings[other.image_id] = []
    write_records(paths, NAME, [PatchRecord(
        NAME, "db", "example/db:1", DB, other.ref, other.image_id,
        (PackageChange("zlib", "1.2", "1.3"),), ("CVE-2026-0002",),
        datetime.now(timezone.utc), "nightly")])
    box.unhealthy_on_patched = True
    outcome = _run(paths)
    assert (outcome.ok, outcome.failed_step) == (False, "health")
    assert "web" in outcome.reason
    assert box.pins == (other,)
    assert box.running() == {"web": WEB, "db": other.image_id}
    assert box.recreates == 2
    (built_ref,) = [ref for ref in box.refs]
    assert box.removed == [built_ref]
    assert [r.service for r in read_records(paths, NAME)] == ["db"]


def test_budget_exceeded_rolls_back_with_step_budget(paths, box, monkeypatch) -> None:
    """The deadline passes while the health wait runs: the wait finishes,
    then the run rolls back."""
    clock = [datetime.now(timezone.utc)]
    monkeypatch.setattr(autofix_run, "_now", lambda: clock[0])
    deadline = clock[0] + timedelta(minutes=30)

    def late() -> None:
        clock[0] = deadline + timedelta(seconds=1)
    box.on_health = late
    outcome = _run(paths, deadline=deadline)
    assert (outcome.ok, outcome.failed_step) == (False, "budget")
    assert box.pins == () and box.running() == {"web": WEB, "db": DB}
    assert len(box.removed) == 1 and read_records(paths, NAME) == ()


def test_scan_still_finding_cve_fails_at_scan(paths, box) -> None:
    box.patched_findings["web"] = [_fd(disposition=Disposition.IGNORED_FIXED)]
    before = dict(box.containers)
    outcome = _run(paths)
    assert (outcome.ok, outcome.failed_step) == (False, "scan")
    assert CVE in outcome.reason and "still in openssl" in outcome.reason
    assert box.containers == before and box.recreates == 0 and box.pins == ()
    assert len(box.removed) == 1


def test_new_quarantine_level_finding_fails_at_scan(paths, box) -> None:
    box.patched_findings["web"] = [_fd("CVE-2026-9999", pkg="libcrypto3")]
    outcome = _run(paths)
    assert outcome.failed_step == "scan" and "CVE-2026-9999" in outcome.reason


def test_not_patchable_fails_at_probe(paths, box) -> None:
    box.probe_result = NotPatchable("no shell or package manager in the image")
    outcome = _run(paths)
    assert outcome.failed_step == "probe" and "no shell" in outcome.reason
    assert box.built == [] and box.recreates == 0


def test_language_package_fails_at_probe(paths, box) -> None:
    box.findings[WEB] = [_fd(pkg="requests", pkg_class=PkgClass.LANG)]
    outcome = _run(paths)
    assert outcome.failed_step == "probe" and "not an OS package" in outcome.reason


def test_pinned_service_is_patched_again_from_its_records_base(paths, box) -> None:
    old = "sha256:" + "b" * 64
    pin = ImagePin("web", pin_ref(NAME, "web", old), old, "autofix")
    box.pins, box.release["web"] = (pin,), old
    box.containers["web"] = ("c-web-0", old)
    box.findings[old] = [_fd()]
    write_records(paths, NAME, [PatchRecord(
        NAME, "web", "example/web:1", WEB, pin.ref, old, (PackageChange("zlib", "1.2", "1.3"),),
        ("CVE-2026-0002",), datetime.now(timezone.utc), "nightly")])
    outcome = _run(paths)
    assert outcome.ok, outcome.reason
    assert box.built == [("web", WEB, {"openssl": "3.0.9", "zlib": "1.3"})]
    (record,) = outcome.records
    assert record.cves == ("CVE-2026-0002", CVE) and record.base_digest == WEB
    assert box.removed == [pin.ref]   # the replaced patch, by its own pin's ref


def test_unexpected_error_rolls_back_and_raises(paths, box, monkeypatch) -> None:
    def broken(*a, **k):
        raise KeyError("a bug")
    monkeypatch.setattr(autofix_run, "wait_healthy", broken)
    with pytest.raises(KeyError):
        _run(paths)
    assert box.pins == () and box.running() == {"web": WEB, "db": DB}
    assert len(box.removed) == 1


def test_rollback_failure_is_added_to_the_reason(paths, box, monkeypatch) -> None:
    box.unhealthy_on_patched = True

    def refuses(pin):
        raise DockerError("image is in use by a container")
    monkeypatch.setattr(autofix_run, "remove_patched", refuses)
    outcome = _run(paths)
    assert outcome.failed_step == "health"
    assert "rollback could not remove the patched image" in outcome.reason


def test_refuses_without_the_project_lock(paths, box) -> None:
    with pytest.raises(RuntimeError, match="project lock"):
        autofix_project_locked(paths, NAME, [_fd()], trigger="nightly",
                               deadline=datetime.now(timezone.utc) + timedelta(minutes=5),
                               quarantined_for_patch=False)
    assert box.built == [] and box.log == []


def test_rollback_recreate_failure_is_reported_structured(paths, box, monkeypatch) -> None:
    """The rollback's recreate fails: the pins are back, the containers are
    not, and the outcome says so in rollback_problems, still at health."""
    box.unhealthy_on_patched = True
    real = box._recreate

    def second_fails(*a, **k):
        if box.recreates:
            raise DockerError("compose up failed")
        real(*a, **k)
    monkeypatch.setattr(autofix_run, "recreate_project", second_fails)
    outcome = _run(paths)
    assert (outcome.ok, outcome.failed_step) == (False, "health")
    assert outcome.rollback_problems
    assert "recreate the previous containers" in outcome.rollback_problems[0]
    assert box.pins == ()
    assert box.log[-1][2]["rollback_problems"] == list(outcome.rollback_problems)


def test_clean_rollback_has_no_problems(paths, box) -> None:
    box.unhealthy_on_patched = True
    assert _run(paths).rollback_problems == ()


def test_every_fixed_version_is_checked_in_the_image(paths, box) -> None:
    box.findings[WEB] = [_fd(fix="3.0.10"), _fd("CVE-2026-2222", fix="3.0.9")]
    outcome = _run(paths, [_fd(), _fd("CVE-2026-2222")])
    assert outcome.ok, outcome.reason
    (_svc, _base, packages), = box.built
    assert [packages, *box.checked] == [{"openssl": "3.0.10"}, {"openssl": "3.0.9"}]


def test_a_fixed_version_the_image_misses_fails_at_build(paths, box) -> None:
    from boxmunge.cve.autofix_build import PatchBuildError
    box.findings[WEB] = [_fd(fix="3.0.10"), _fd("CVE-2026-2222", fix="3.0.9")]
    box.check_error = PatchBuildError("openssl 3.0.9 is below the fixed 3.0.10")
    outcome = _run(paths, [_fd(), _fd("CVE-2026-2222")])
    assert outcome.failed_step == "build" and len(box.removed) == 1


def test_deadline_already_past_scans_nothing(paths, box) -> None:
    outcome = _run(paths, deadline=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert outcome.failed_step == "budget" and box.scans == 0


def test_the_two_scan_failures_read_differently(paths, box) -> None:
    from boxmunge.cve.scanner import ScannerError
    box.scan_error = ScannerError("trivy timed out")
    outcome = _run(paths)
    assert outcome.failed_step == "scan" and "the scan of the running images" in outcome.reason


# ---------- the journal: a run killed mid-swap ----------


def test_the_journal_is_kept_from_the_swap_until_the_run_is_over(paths, box) -> None:
    from boxmunge.cve.autofix_record import read_journal
    seen = []
    box.on_health = lambda: seen.append(read_journal(paths, NAME))
    assert _run(paths).ok
    (journal,) = seen
    assert journal.pins_before == () and [p.service for p in journal.built] == ["web"]
    assert read_journal(paths, NAME) is None


def test_a_rolled_back_run_removes_its_journal(paths, box) -> None:
    from boxmunge.cve.autofix_record import read_journal
    seen = []
    box.on_health = lambda: seen.append(read_journal(paths, NAME))
    box.unhealthy_on_patched = True
    assert _run(paths).failed_step == "health"
    assert len(seen) == 2 and all(j is not None for j in seen)  # the patch's, the rollback's
    assert read_journal(paths, NAME) is None


def test_a_killed_run_is_rolled_back_from_its_journal(paths, box) -> None:
    from boxmunge.cve.autofix_record import AutofixJournal, read_journal, write_journal
    patched = "sha256:" + "e" * 64
    built = ImagePin("web", pin_ref(NAME, "web", patched), patched, "autofix")
    write_journal(paths, NAME, AutofixJournal(datetime.now(timezone.utc), (), (), (built,)))
    box.pins, box.containers["web"] = (built,), ("c-web-9", patched)
    with project_lock(NAME, paths):
        assert autofix_run.recover_interrupted(paths, NAME, patch_cves=()) == ()
        assert autofix_run.recover_interrupted(paths, NAME, patch_cves=()) is None   # nothing left to undo
    assert box.pins == () and box.running()["web"] == WEB
    assert box.removed == [built.ref] and read_journal(paths, NAME) is None
    assert any(level == "error" and "interrupted" in msg for level, msg, _ in box.log)


def _repatch_setup(paths, box) -> tuple[ImagePin, PatchRecord]:
    """web already runs an earlier patch, which this run replaces."""
    old = "sha256:" + "b" * 64
    pin = ImagePin("web", pin_ref(NAME, "web", old), old, "autofix")
    box.pins, box.release["web"] = (pin,), old
    box.containers["web"] = ("c-web-0", old)
    box.findings[old] = [_fd()]
    record = PatchRecord(
        NAME, "web", "example/web:1", WEB, pin.ref, old, (PackageChange("zlib", "1.2", "1.3"),),
        ("CVE-2026-0002",), datetime.now(timezone.utc), "nightly")
    write_records(paths, NAME, [record])
    return pin, record


def test_the_journal_goes_after_the_records_and_before_the_replaced_image(
        paths, box, monkeypatch) -> None:
    """A kill before the journal goes is recovered whole: the journal restores
    the pins and the records the run found."""
    from boxmunge.cve.autofix_record import read_journal
    pin, _ = _repatch_setup(paths, box)
    seen: dict[str, object] = {}
    real_write, real_remove = autofix_run.write_records, autofix_run.remove_patched

    def write(p, project, records):
        seen["records"] = read_journal(paths, NAME)
        real_write(p, project, records)

    def remove(p):
        seen["remove"] = read_journal(paths, NAME)
        real_remove(p)

    monkeypatch.setattr(autofix_run, "write_records", write)
    monkeypatch.setattr(autofix_run, "remove_patched", remove)
    assert _run(paths).ok
    assert seen["records"] is not None and seen["remove"] is None
    assert box.removed == [pin.ref]


def test_a_journal_left_after_a_patch_keeps_what_recovery_restores(paths, box,
                                                                   monkeypatch) -> None:
    """The journal could not be removed once the patch was healthy: the image
    it replaced is kept, so a recovery from the journal restores a pin that
    still names an image, and the records it had."""
    from boxmunge.cve.autofix_record import read_journal
    from boxmunge.state import StateError
    pin, record = _repatch_setup(paths, box)
    real_remove = autofix_run.remove_journal

    def stuck(p, project):
        raise StateError("cannot remove the autofix journal: read-only file system")

    monkeypatch.setattr(autofix_run, "remove_journal", stuck)
    outcome = _run(paths)
    assert outcome.ok and box.removed == []          # the replaced patch is kept
    assert read_journal(paths, NAME) is not None
    assert any(level == "error" and "replaced are kept" in msg for level, msg, _ in box.log)
    assert read_records(paths, NAME) == outcome.records
    monkeypatch.setattr(autofix_run, "remove_journal", real_remove)
    with project_lock(NAME, paths):
        assert autofix_run.recover_interrupted(paths, NAME, patch_cves=()) == ()
    assert box.pins == (pin,) and box.running()["web"] == pin.image_id
    assert read_records(paths, NAME) == (record,)     # no record claims the undone patch
    assert pin.ref not in box.removed and read_journal(paths, NAME) is None


def test_cve_gone_from_the_running_images_is_nothing_to_patch(paths, box) -> None:
    box.findings[WEB] = []   # e.g. a container update moved it onto a fixed upstream
    outcome = _run(paths)
    assert (outcome.ok, outcome.failed_step, outcome.nothing_to_patch) == (False, "scan", True)
    assert box.built == [] and box.recreates == 0


def test_other_scan_failures_are_not_nothing_to_patch(paths, box) -> None:
    box.patched_findings["web"] = [_fd(disposition=Disposition.IGNORED_FIXED)]
    assert _run(paths).nothing_to_patch is False


def test_nothing_to_patch_is_logged_as_an_operation(paths, box) -> None:
    box.findings[WEB] = []
    _run(paths)
    assert not [m for level, m, _ in box.log if level == "error"]
    assert any("nothing to patch" in m for level, m, _ in box.log if level == "op")


def test_paused_project_is_refused_at_swap_nothing_started(paths, box) -> None:
    from boxmunge.pause import write_paused_state
    write_paused_state(NAME, paths)
    before = dict(box.containers)
    outcome = _run(paths)
    assert (outcome.ok, outcome.failed_step) == (False, "swap")
    assert "paused" in outcome.reason and outcome.rollback_problems == ()
    assert box.containers == before and box.recreates == 0 and box.pins == ()
    assert len(box.removed) == 1


def test_quarantined_project_is_refused_unless_quarantined_for_the_patch(paths, box) -> None:
    from tests.test_commands.cve_helpers import seed_quarantine
    seed_quarantine(paths, NAME)
    refused = _run(paths)
    assert refused.failed_step == "swap" and "CVE-quarantined" in refused.reason
    assert box.recreates == 0
    seed_quarantine(paths, NAME, cve_id=CVE)
    dark = _run(paths, dark=True)
    assert dark.ok, dark.reason


def test_dark_patch_refused_when_quarantined_for_another_cve(paths, box) -> None:
    """Quarantined for CVE-A, the dark patch is for CVE-B: nothing starts;
    the patch waits until that quarantine is resolved."""
    from tests.test_commands.cve_helpers import seed_quarantine
    seed_quarantine(paths, NAME, cve_id="CVE-2026-0404")
    before = dict(box.containers)
    outcome = _run(paths, dark=True)
    assert (outcome.ok, outcome.failed_step) == (False, "swap")
    assert "CVE-2026-0404" in outcome.reason and "does not fix" in outcome.reason
    assert box.containers == before and box.recreates == 0 and box.pins == ()


UP = "sha256:" + "f" * 64


def _run_on_upstream(paths, findings=None, upstream=None):
    from boxmunge.docker_containers import LocalImage
    with project_lock(NAME, paths):
        return autofix_run.repatch_on_upstream_locked(
            paths, NAME, findings if findings is not None else [_fd()],
            upstream=upstream or {"web": LocalImage(UP, ("example/web@sha256:" + "f" * 64,))},
            deadline=datetime.now(timezone.utc) + timedelta(minutes=30))


def test_repatch_on_upstream_builds_from_the_new_upstream_not_the_old_base(paths,
                                                                          box) -> None:
    """web runs a patch of WEB; upstream shipped UP, which still carries the
    CVE: the new patch is built FROM UP, with UP's own packages, and the
    record names UP as its base."""
    pin, record = _repatch_setup(paths, box)
    box.findings[pin.image_id] = []          # the running patch is clean
    box.findings[UP] = [_fd()]
    outcome = _run_on_upstream(paths)
    assert outcome.ok, outcome.reason
    [(svc, base, packages)] = box.built
    assert (svc, base, packages) == ("web", UP, {"openssl": "3.0.9"})   # not zlib, not WEB
    [new] = outcome.records
    assert (new.base_digest, new.base_ref) == (UP, "example/web@sha256:" + "f" * 64)
    assert new.cves == (CVE,) and new.trigger == "nightly"
    assert read_records(paths, NAME) == (new,)
    assert box.removed == [pin.ref]          # the old patch went


def test_repatch_on_upstream_failure_keeps_the_old_patch(paths, box) -> None:
    pin, record = _repatch_setup(paths, box)
    box.findings[pin.image_id] = []
    box.findings[UP] = [_fd()]
    box.unhealthy_on_patched = True
    outcome = _run_on_upstream(paths)
    assert (outcome.ok, outcome.failed_step) == (False, "health")
    assert box.pins == (pin,) and box.running()["web"] == pin.image_id
    assert read_records(paths, NAME) == (record,)


def test_repatch_on_upstream_names_a_service_that_is_not_pinned(paths, box) -> None:
    with pytest.raises(ValueError, match="not pinned"):
        _run_on_upstream(paths)
