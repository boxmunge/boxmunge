# SPDX-License-Identifier: Apache-2.0
"""Upstream catch-up (commands.autofix_upstream; CVE autofix flowcharts,
chart 4): a pinned patched image is kept while upstream has nothing new,
gives way to a new upstream image that is clean, and is rebuilt FROM a new
upstream image that still needs the patch. The pins, the scan, the recreate,
the health wait and the patch runner are faked at the module's seams; the
patch records are the real files."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from boxmunge.commands import autofix_upstream as up
from boxmunge.cve import autofix_plan
from boxmunge.cve.autofix_record import PackageChange, PatchRecord, read_records, write_records
from boxmunge.cve.autofix_run import AutofixOutcome
from boxmunge.cve.policy_types import Disposition, FindingDisposition, ProjectDecision
from boxmunge.cve.scanner import Severity
from boxmunge.deployed_inventory import DeployedInventory, DeployedService
from boxmunge.docker_containers import LocalImage, ProjectContainer
from boxmunge.fileutil import project_lock
from boxmunge.image_pins import ImagePin, pin_ref
from tests.test_commands.cve_helpers import finding, make_box

P = "shop"
CVE = "CVE-2026-1111"
BASE = "sha256:" + "a" * 64        # the upstream image the patch was built from
PATCHED = "sha256:" + "b" * 64     # the patched image web runs
NEW = "sha256:" + "c" * 64         # the image upstream ships tonight
NEW_REF = "example/web@sha256:" + "c" * 64


def _fd(cve: str = CVE, disposition: Disposition = Disposition.QUARANTINE,
        pkg: str = "openssl") -> FindingDisposition:
    return FindingDisposition(finding(cve, pkg=pkg, fix="3.0.9"), Severity.CRITICAL, 0,
                              Severity.CRITICAL, disposition, None, "")


class Box:
    def __init__(self, tmp_path, monkeypatch) -> None:
        self.paths = make_box(tmp_path, projects=(P,))
        self.pin = ImagePin("web", pin_ref(P, "web", PATCHED), PATCHED, "autofix")
        self.pins: tuple[ImagePin, ...] = (self.pin,)
        self.record = PatchRecord(P, "web", "example/web@sha256:" + "a" * 64, BASE,
                                  self.pin.ref, PATCHED, (PackageChange("openssl", "3.0.1",
                                                                        "3.0.9"),),
                                  (CVE,), datetime.now(timezone.utc), "nightly")
        write_records(self.paths, P, [self.record])
        self.findings: dict[str, list[FindingDisposition]] = {NEW: [], PATCHED: []}
        self.running = PATCHED
        self.unhealthy_on: set[str] = set()
        self.recreates: list[str] = []
        self.removed: list[str] = []
        self.repatched: list[tuple[tuple[str, ...], dict]] = []
        self.repatch_outcome = AutofixOutcome(True, None, "patched web", ())
        for name, fake in [("read_pins", lambda paths, project: self.pins),
                           ("write_pins", self._write_pins),
                           ("clear_pins", lambda paths, project: self._write_pins(paths,
                                                                                  project, ())),
                           ("load_project_meta", lambda paths, project: SimpleNamespace(autofix=True)),
                           ("load_deployed_inventory", self._inventory),
                           ("recreate_project", self._recreate),
                           ("wait_healthy", self._wait_healthy),
                           ("remove_patched", lambda pin: self.removed.append(pin.ref)),
                           ("local_image", lambda ref: LocalImage(NEW, (NEW_REF,))
                            if ref == NEW else None),
                           ("repatch_on_upstream_locked", self._repatch)]:
            monkeypatch.setattr(up, name, fake)
        monkeypatch.setattr(autofix_plan, "scan_images", self._scan)

    def _write_pins(self, paths, project, pins) -> None:
        self.pins = tuple(pins)

    def _inventory(self, project_dir, files, project):
        return DeployedInventory(project, {"web": DeployedService(
            "web", "example/web:1", False, True, (ProjectContainer(
                f"{project}-web-1", "web", self.running, (), True, "healthy", False, None,
                "always"),))})

    def _scan(self, paths, project, meta, images, label):
        return {svc: ProjectDecision(P, img, tuple(self.findings[img]), False, False,
                                     datetime.now(timezone.utc))
                for svc, img in images.items()}

    def _recreate(self, paths, project, files, *, component, patch_cves=()):
        pinned = {p.service: p.image_id for p in self.pins}
        self.running = pinned.get("web", NEW)
        self.recreates.append(self.running)

    def _wait_healthy(self, project, services, one_shots=frozenset()):
        bad = ["web"] if self.running in self.unhealthy_on else []
        return (not bad, bad)

    def _repatch(self, paths, project, findings, *, upstream, deadline):
        self.repatched.append((tuple(sorted(fd.finding.cve_id for fd in findings)),
                               dict(upstream)))
        return self.repatch_outcome

    def reconcile(self, digest: str = NEW):
        with project_lock(P, self.paths):
            return up.reconcile_pinned_service(self.paths, P, "web", digest)


@pytest.fixture
def box(tmp_path, monkeypatch) -> Box:
    return Box(tmp_path, monkeypatch)


def test_no_new_upstream_keeps_pin(box) -> None:
    assert box.reconcile(BASE) == "kept"
    assert box.pins == (box.pin,) and read_records(box.paths, P) == (box.record,)
    assert box.recreates == [] and box.repatched == [] and box.removed == []


def test_clean_upstream_switches_and_clears_record(box) -> None:
    box.findings[NEW] = [_fd("CVE-2026-2222", Disposition.INFORMATIONAL)]   # not quarantine-level
    assert box.reconcile() == "switched"
    assert box.pins == () and read_records(box.paths, P) == ()
    assert box.recreates == [NEW] and box.running == NEW
    assert box.removed == [box.pin.ref]       # the old patch is gone
    assert box.repatched == []


def test_vulnerable_upstream_repatched_from_new_digest(box) -> None:
    box.findings[NEW] = [_fd(), _fd("CVE-2026-2222", Disposition.INFORMATIONAL)]
    assert box.reconcile() == "repatched"
    [(cves, upstream)] = box.repatched
    assert cves == (CVE,)                                  # only what needs patching
    assert upstream == {"web": LocalImage(NEW, (NEW_REF,))}  # FROM the new upstream
    assert box.recreates == []                             # the runner swaps it in


def test_a_new_quarantine_level_finding_upstream_is_not_clean(box) -> None:
    """Upstream fixed the patched CVE but brought a quarantine-level one the
    patched image does not have: it is patched too, never switched to."""
    box.findings[NEW] = [_fd("CVE-2026-3333")]
    assert box.reconcile() == "repatched"
    assert box.repatched[0][0] == ("CVE-2026-3333",)
    assert box.pins == (box.pin,)


def test_a_quarantine_level_finding_the_patch_has_too_is_not_new(box) -> None:
    box.findings[NEW] = [_fd("CVE-2026-3333")]
    box.findings[PATCHED] = [_fd("CVE-2026-3333")]
    assert box.reconcile() == "switched"


def test_failed_repatch_keeps_the_old_patch(box) -> None:
    box.findings[NEW] = [_fd()]
    box.repatch_outcome = AutofixOutcome(False, "probe", "no package manager", ())
    with pytest.raises(up.UpstreamFailed, match="no package manager") as e:
        box.reconcile()
    assert e.value.rollback_problems == ()
    assert box.pins == (box.pin,) and read_records(box.paths, P) == (box.record,)


def test_unhealthy_upstream_rolls_back_to_the_patch(box) -> None:
    box.unhealthy_on = {NEW}
    with pytest.raises(up.UpstreamFailed, match="not healthy") as e:
        box.reconcile()
    assert e.value.rollback_problems == ()
    assert box.pins == (box.pin,) and read_records(box.paths, P) == (box.record,)
    assert box.recreates == [NEW, PATCHED] and box.running == PATCHED
    assert box.removed == []


def test_a_rollback_that_does_not_finish_says_so(box) -> None:
    box.unhealthy_on = {NEW, PATCHED}
    with pytest.raises(up.UpstreamFailed) as e:
        box.reconcile()
    assert any("healthy" in p for p in e.value.rollback_problems)


def test_a_project_kept_down_is_not_switched(box) -> None:
    from boxmunge.pause import write_paused_state
    write_paused_state(P, box.paths)
    with pytest.raises(up.UpstreamFailed, match="paused"):
        box.reconcile()
    assert box.recreates == [] and box.pins == (box.pin,)


def test_a_pinned_service_with_no_record_fails(box) -> None:
    write_records(box.paths, P, [])
    with pytest.raises(up.UpstreamFailed, match="no patch record"):
        box.reconcile()


def test_the_caller_holds_the_project_lock(box) -> None:
    with pytest.raises(RuntimeError, match="project lock"):
        up.reconcile_pinned_service(box.paths, P, "web", NEW)


# reconcile_upstream: the release's own image, pulled, for each pinned service.

@pytest.fixture
def release(box, monkeypatch):
    """The release's images without its pins, and the pull."""
    seen: dict = {"pulled": [], "images": {"web": "example/web:1"}, "drift": {}}

    def pull(paths, project, target, service, ref):
        seen["pulled"].append((service, ref))
        if seen["drift"]:
            raise up.UpstreamFailed(f"held back: {seen['drift'][service]}")
        return NEW

    monkeypatch.setattr(up, "_release_images", lambda paths, project: _Release(seen["images"]))
    monkeypatch.setattr(up, "_pull_upstream", pull)
    return seen


class _Release:
    def __init__(self, images) -> None:
        self.images, self.target = images, object()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


def _catch_up(box, start_by=None):
    with project_lock(P, box.paths):
        return up.reconcile_upstream(
            box.paths, P, start_by=start_by or datetime.now(timezone.utc) + timedelta(hours=1))


def test_reconcile_upstream_pulls_the_release_image_and_switches(box, release) -> None:
    [result] = _catch_up(box)
    assert release["pulled"] == [("web", "example/web:1")]
    assert (result.service, result.outcome, result.cves) == ("web", "switched", (CVE,))


def test_reconcile_upstream_skips_a_build_service(box, release) -> None:
    release["images"] = {"web": None}
    assert _catch_up(box) == ()
    assert release["pulled"] == [] and box.pins == (box.pin,)


def test_reconcile_upstream_reports_a_failure(box, release) -> None:
    release["drift"] = {"web": "image user app -> root"}
    [result] = _catch_up(box)
    assert result.outcome is None and "image user app -> root" in result.reason
    assert box.pins == (box.pin,)


def test_reconcile_upstream_starts_nothing_after_its_start_by(box, release) -> None:
    assert _catch_up(box, datetime.now(timezone.utc) - timedelta(seconds=1)) == ()
    assert release["pulled"] == []


def test_reconcile_upstream_with_no_pins_does_nothing(box, release) -> None:
    box.pins = ()
    assert _catch_up(box) == ()
    assert release["pulled"] == []


def test_reconcile_upstream_leaves_autofix_off_alone(box, release, monkeypatch) -> None:
    monkeypatch.setattr(up, "load_project_meta",
                        lambda paths, project: SimpleNamespace(autofix=False))
    assert _catch_up(box) == ()
    assert release["pulled"] == []


def test_release_images_are_the_releases_own_without_its_pins(box, monkeypatch) -> None:
    rendered = {}

    def render(paths, manifest, user_compose, users=None, *, installing=False):
        rendered["installing"] = installing
        return "services: {}\n"

    monkeypatch.setattr(up, "load_manifest", lambda path: {"project": P})
    monkeypatch.setattr(up, "load_user_compose", lambda path, project: {})
    monkeypatch.setattr(up, "render_compose_override", render)
    monkeypatch.setattr(up, "resolved_services", lambda target: ({}, {
        "web": {"image": "example/web:1"},
        "app": {"image": "boxmunge.invalid/shop/app", "build": {"context": "."}},
        "worker": {"image": "boxmunge.invalid/shop/app"},
    }))
    with up._release_images(box.paths, P) as release:
        assert release.images == {"web": "example/web:1", "app": None, "worker": None}
        assert release.target.compose.files[0] == "compose.yml"
    assert rendered == {"installing": True}


def test_pull_upstream_returns_the_new_image(box, monkeypatch) -> None:
    images = {"example/web:1": LocalImage(BASE, ())}
    pulled = []

    def pull(cwd, files, *, project_name, services):
        pulled.append((project_name, services))
        images["example/web:1"] = LocalImage(NEW, ())

    monkeypatch.setattr(up, "compose_pull", pull)
    monkeypatch.setattr(up, "local_image", lambda ref: images.get(ref))
    seen = {}
    monkeypatch.setattr(up, "guard_pull", lambda paths, project, refs, before, component:
                        seen.update(refs=refs, before=before) or {})
    target = SimpleNamespace(compose=SimpleNamespace(cwd=box.paths.project_dir(P),
                                                     files=["compose.yml", "/x.yml"]))
    assert up._pull_upstream(box.paths, P, target, "web", "example/web:1") == NEW
    assert pulled == [(P, ["web"])]
    assert seen == {"refs": {"web": "example/web:1"}, "before": {"web": BASE}}
    monkeypatch.setattr(up, "guard_pull", lambda *a, **k: {"web": "image user app -> root"})
    with pytest.raises(up.UpstreamFailed, match="held back: image user app -> root"):
        up._pull_upstream(box.paths, P, target, "web", "example/web:1")


# The nightly autofix catches a project up with upstream before patching it.

@pytest.fixture
def nightly(tmp_path, monkeypatch):
    from tests.test_commands.test_autofix_nightly import Box as NightlyBox
    nb = NightlyBox(tmp_path, monkeypatch)
    nb.calls = []
    nb.results = ()
    real_runner = nb.runner

    def reconcile(paths, project, *, start_by):
        nb.calls.append(("upstream", project, start_by))
        return nb.results

    def runner(*a, **k):
        nb.calls.append(("patch", a[1]))
        return real_runner(*a, **k)

    from boxmunge.commands import autofix_nightly
    monkeypatch.setattr(autofix_nightly, "reconcile_upstream", reconcile)
    monkeypatch.setattr(autofix_nightly, "autofix_project_locked", runner)
    return nb


def test_nightly_catches_up_before_patching_and_digests_it(nightly) -> None:
    from boxmunge.cve.autofix_policy import AUTOFIX_NIGHTLY_BUDGET
    nightly.scan()
    nightly.results = (up.UpstreamResult("demo", "web", "switched", (CVE,)),)
    before = datetime.now(timezone.utc)
    nightly.update()
    [(what, project, start_by), patch] = nightly.calls
    assert (what, project, patch) == ("upstream", "demo", ("patch", "demo"))
    from boxmunge.cve.autofix_policy import NIGHTLY_AUTOFIX_WINDOW
    assert start_by <= before + NIGHTLY_AUTOFIX_WINDOW - AUTOFIX_NIGHTLY_BUDGET
    [(title, body, priority)] = nightly.pushover.sent
    assert priority == -1
    assert "switched to upstream: demo/web" in body
    assert "patched: demo: CVE-2026-0001" in body


def test_kept_is_silent(nightly) -> None:
    nightly.results = (up.UpstreamResult("demo", "web", "kept", (CVE,)),)
    nightly.update()                   # nothing scanned: nothing to patch either
    assert [c[0] for c in nightly.calls] == ["upstream"]
    assert nightly.pushover.sent == []


def test_repatched_and_failed_lines(nightly) -> None:
    nightly.results = (up.UpstreamResult("demo", "web", "repatched", (CVE,)),
                       up.UpstreamResult("demo", "db", None, ("CVE-2026-7",),
                                         "the new upstream image is held back: x"))
    nightly.update()
    [(title, body, priority)] = nightly.pushover.sent
    assert "re-patched on new upstream: demo/web" in body
    assert ("could not catch up with upstream: demo/db: the new upstream image is held "
            "back: x") in body
    assert title == ("[box.example.com] Nightly autofix: 1 project patched, 1 could not "
                     "be patched")


def test_a_catch_up_whose_rollback_did_not_finish_is_urgent(nightly) -> None:
    nightly.results = (up.UpstreamResult("demo", "web", None, (CVE,), "not healthy on x",
                                         ("rollback could not restore the image pins",)),)
    nightly.update()
    [(title, body, priority)] = nightly.pushover.sent
    assert priority == 1 and CVE in title
    assert "rollback could not restore the image pins" in body


@pytest.mark.parametrize("status", ["failed", "paused"])
def test_no_catch_up_after_a_failed_or_paused_update(nightly, status) -> None:
    nightly.update_status = status
    nightly.update()
    assert [c for c in nightly.calls if c[0] == "upstream"] == []


def test_no_catch_up_for_a_project_container_update_does_not_update(nightly) -> None:
    from boxmunge.commands import autofix_nightly
    with project_lock("demo", nightly.paths):
        autofix_nightly.run_nightly_autofix(nightly.paths, "demo",
                                            until=autofix_nightly.window_end())
    assert nightly.calls == []


def test_reconcile_upstream_leaves_a_blocked_project_alone(box, release) -> None:
    from boxmunge.pause import write_paused_state
    write_paused_state(P, box.paths)
    assert _catch_up(box) == ()
    assert release["pulled"] == []


def test_a_project_a_catch_up_left_mixed_is_not_patched_tonight(nightly) -> None:
    nightly.scan()
    nightly.results = (up.UpstreamResult("demo", "web", None, (CVE,), "not healthy on x",
                                         ("rollback could not restore the image pins",)),)
    nightly.update()
    assert [c[0] for c in nightly.calls] == ["upstream"]
    urgent, digest = nightly.pushover.sent
    assert urgent[2] == 1
    assert "skipped: demo: catching it up with upstream did not roll back cleanly" in digest[1]
