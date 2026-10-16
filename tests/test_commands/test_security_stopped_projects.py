# SPDX-License-Identifier: Apache-2.0
"""A project the platform stopped on purpose (paused, quarantined, stopped by
the health monitor) is scanned by the images `compose up` would start, not
by its containers, which may be gone. The scan state records that basis,
and `security resume` therefore checks exactly what the lift will run."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from boxmunge.commands import security_resume, security_scan_core
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.cve.scan_state import BASIS_CONTAINERS, BASIS_STARTUP_IMAGES, read_scan_state
from boxmunge.docker_containers import LocalImage
from boxmunge.pause import write_paused_state
from boxmunge.state import write_state
from tests.test_commands.cve_helpers import Docker, make_box, scan_result, seed_quarantine

_RUNNING = "sha256:" + "1" * 64
_PULLED = "sha256:" + "2" * 64
_BUILT = "sha256:" + "3" * 64
_KEV = KevCatalog(cve_ids=frozenset(), fetched_at=datetime.now(timezone.utc))


@pytest.fixture
def box(tmp_path, monkeypatch, fake_containers):
    """'demo': web from image demo-web:1 (its container runs _RUNNING) and a
    build-only worker; records the refs Trivy is asked to scan."""
    paths = make_box(tmp_path, services=("web", "worker"), images={"web": "demo-web:1"})
    fake_containers.run("demo", "web", _RUNNING)
    fake_containers.run("demo", "worker", _BUILT)
    fake_containers.images["demo-web:1"] = LocalImage(_RUNNING, ())
    fake_containers.images["demo-worker"] = LocalImage(_BUILT, ())
    scanned: list[str] = []

    def trivy(ref, timeout):
        scanned.append(ref)
        return scan_result(ref)

    monkeypatch.setattr(security_scan_core, "scan_image", trivy)
    Docker(monkeypatch)  # a quarantine is re-asserted on every scan
    paths.scanned = scanned
    return paths


def _scan(paths):
    return scan_one_project(paths, "demo", in_grace=True, kev=_KEV)


def test_running_project_is_scanned_by_its_containers(box, fake_containers):
    fake_containers.images["demo-web:1"] = LocalImage(_PULLED, ())  # a pull moved the tag
    scan = _scan(box)
    assert box.scanned == [_RUNNING, _BUILT] and scan.complete
    state = read_scan_state(box.project_scan_state("demo"))
    assert (state["basis"], state["stopped_reason"]) == (BASIS_CONTAINERS, None)


def test_paused_project_scans_what_resume_would_start(box, fake_containers):
    """The paused pre-pull moved the tag; resume would start the pulled image.
    The container the marker did not stop (a failed `compose stop`, say)
    still runs the old one, so that is scanned too."""
    write_paused_state("demo", box)
    fake_containers.images["demo-web:1"] = LocalImage(_PULLED, ())
    scan = _scan(box)
    assert box.scanned == [_RUNNING, _PULLED, _BUILT] and scan.complete
    state = read_scan_state(box.project_scan_state("demo"))
    assert (state["basis"], state["stopped_reason"]) == (BASIS_STARTUP_IMAGES, "paused")


def test_quarantined_project_without_containers_is_still_complete(box, fake_containers):
    seed_quarantine(box)
    fake_containers.remove("demo")  # e.g. `docker container prune`
    scan = _scan(box)
    assert box.scanned == [_RUNNING, _BUILT] and scan.complete
    assert (scan.basis, scan.stopped_reason) == (BASIS_STARTUP_IMAGES, "quarantined")


def test_stopped_basis_never_covers_less_than_the_containers(box, fake_containers):
    """One-off and orphan containers survive `compose stop`; they are scanned."""
    seed_quarantine(box)
    fake_containers.run("demo", "web", _PULLED, oneoff=True)
    fake_containers.run("demo", "retired", _BUILT)
    _scan(box)
    assert box.scanned == [_RUNNING, _PULLED, _BUILT, _BUILT]


def test_monitor_stopped_project_scans_what_recover_would_start(box, fake_containers):
    write_state(box.project_health_state("demo"), {
        "status": "critical_stopped", "stopped_at": "2026-10-01T03:00:00+00:00",
    })
    fake_containers.remove("demo")  # compose down removed them
    scan = _scan(box)
    assert box.scanned == [_RUNNING, _BUILT] and scan.complete
    assert scan.stopped_reason == "stopped by the health monitor"


def test_missing_startup_image_makes_the_scan_incomplete(box, fake_containers):
    write_paused_state("demo", box)
    fake_containers.images["demo-worker"] = None
    scan = _scan(box)
    assert scan.unidentified_services == ("worker",)
    assert scan.incomplete_reasons() == [
        "service 'worker': the image `compose up` would start (demo-worker) is not "
        "in the local image store; pull or build it, then scan again"]
    assert json.loads(box.project_scan_state("demo").read_text())["unscanned"] == \
        scan.incomplete_reasons()


@pytest.fixture
def resume(monkeypatch):
    lifted: list[str] = []
    monkeypatch.setattr(security_resume, "refresh_db", lambda: None)
    monkeypatch.setattr(security_resume, "prepare_caddy_config", lambda p, m: None)
    monkeypatch.setattr(security_resume, "prepare_compose_override",
                        lambda p, m, component=None: None)
    monkeypatch.setattr(security_resume, "run_smoke", lambda p, paths_: (True, "ok"))
    monkeypatch.setattr(security_resume, "lift_quarantine",
                        lambda *a, **k: lifted.append("lift"))
    return lifted


def test_resume_of_a_pruned_quarantined_project_scans_and_lifts(
    box, fake_containers, resume, capsys,
):
    seed_quarantine(box)
    fake_containers.remove("demo")
    assert cmd_security_resume(["demo"], box) == 0
    assert resume == ["lift"]
    assert box.scanned == [_RUNNING, _BUILT]
    assert "every image the lift will start scanned" in capsys.readouterr().out


def test_resume_refuses_when_what_it_would_start_is_missing(
    box, fake_containers, resume, capsys,
):
    seed_quarantine(box)
    fake_containers.remove("demo")
    fake_containers.images["demo-web:1"] = None
    assert cmd_security_resume(["demo"], box) == 1
    assert resume == [] and is_quarantined("demo", box)
    assert "(demo-web:1) is not in the local image store" in capsys.readouterr().err


def test_status_json_names_the_scan_basis(box):
    from boxmunge.commands.security_views import format_project_json
    from boxmunge.manifest import load_manifest
    write_paused_state("demo", box)
    _scan(box)
    payload = json.loads(format_project_json(
        load_manifest(box.project_manifest("demo")), posture="balanced",
        dangerously_disable_quarantine=False, quarantined=False, quarantine_state=None,
        scan_state=read_scan_state(box.project_scan_state("demo")), active_suppressions=(),
    ))
    assert (payload["cve"]["scan_basis"], payload["cve"]["stopped_reason"]) == (
        BASIS_STARTUP_IMAGES, "paused")
