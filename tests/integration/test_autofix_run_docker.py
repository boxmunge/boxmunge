# SPDX-License-Identifier: Apache-2.0
"""One autofix end to end, on a real daemon.

A project whose web service runs alpine:3.19.0, released before Alpine
fixed its busybox, is deployed for real. Trivy is the only stub: an image
carries the CVE unless it is a patched one (BASE_LABEL). The runner builds
the patch from the image the container runs, pins it, recreates the
service and waits for it: on success the service runs the pinned image and
the patch is recorded; when the patched image fails its health check, the
project is back on its own image, unpinned, and the patched image is gone.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.commands import quarantine_gate
from boxmunge.cve import autofix_plan
from boxmunge.container_recreate import recreate_project
from boxmunge.cve.autofix_build import BASE_LABEL, build_patched, probe
from boxmunge.cve.autofix_record import (
    PackageChange, PatchRecord, read_records, write_records,
)
from boxmunge.cve.autofix_run import autofix_project_locked
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.scanner import Severity
from boxmunge.fileutil import project_lock
from boxmunge.image_pins import ImagePin, read_pins, write_pins
from tests.integration import nonroot_cases as nc
from tests.integration.conftest import skip_no_docker
from tests.test_commands.cve_helpers import finding, scan_result

pytestmark = [pytest.mark.integration, skip_no_docker]

ALPINE = "alpine:3.19.0"
CVE = "CVE-2026-4343"
FIXED = "1.36.1-r16"   # a busybox Alpine 3.19 shipped after 3.19.0
NOBODY = {"user": "65534:65534"}


def _inspect(ref: str, fmt: str) -> str:
    return subprocess.run(["docker", "image", "inspect", "--format", fmt, ref],
                          capture_output=True, text=True, check=True).stdout.strip()


def _old_busybox() -> str:
    return subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "/bin/sh", ALPINE, "-c",
         "apk list --installed busybox | cut -d' ' -f1 | sed 's/^busybox-//'"],
        capture_output=True, text=True, check=True, timeout=120).stdout.strip()


def _containers(p: str) -> dict[str, tuple[str, str]]:
    """{service: (container ID, image ID)} of the project's containers."""
    ids = subprocess.run(["docker", "ps", "-aq", "--filter",
                          f"label=com.docker.compose.project={p}"],
                         capture_output=True, text=True, check=True).stdout.split()
    out = {}
    for doc in json.loads(subprocess.run(["docker", "inspect", *ids], capture_output=True,
                                         text=True, check=True).stdout):
        out[doc["Config"]["Labels"]["com.docker.compose.service"]] = (doc["Id"], doc["Image"])
    return out


@pytest.fixture
def deployed(int_paths, capsys, monkeypatch):
    """A deployed project and a deploy function for its web service's
    healthcheck; torn down after the test."""
    old = _old_busybox()
    assert old and old != FIXED, old

    def scan(ref: str, timeout=None):
        labels = json.loads(_inspect(ref, "{{json .Config.Labels}}")) or {}
        vulnerable = BASE_LABEL not in labels
        found = replace(finding(CVE, pkg="busybox", fix=FIXED), installed_version=old)
        return scan_result(ref, (found,) if vulnerable else ())
    monkeypatch.setattr("boxmunge.commands.security_scan_core.scan_image", scan)
    monkeypatch.setattr(quarantine_gate, "refresh_db", lambda: None)
    now = datetime.now(timezone.utc)
    kev = KevCatalog(frozenset({CVE}), now, now, "test")
    monkeypatch.setattr(autofix_plan, "load_kev", lambda paths: kev)
    monkeypatch.setattr("boxmunge.container_recreate.NO_HEALTHCHECK_GRACE_SEC", 0)
    monkeypatch.setattr("boxmunge.container_recreate.HEALTHCHECK_POLL_INTERVAL_SEC", 1)
    p = f"bmaf{uuid.uuid4().hex[:8]}"

    def deploy(healthcheck: str | None, *, side: bool = False) -> None:
        web = {"image": ALPINE, "command": nc.SLEEP, "restart": "unless-stopped"}
        if healthcheck:
            web["healthcheck"] = {"test": ["CMD-SHELL", healthcheck], "interval": "1s",
                                  "retries": 2, "start_period": "0s"}
        services = {"web": web, **({"side": {"image": ALPINE, "command": nc.SLEEP,
                                             "restart": "unless-stopped"}} if side else {})}
        rc, out = nc.deploy(int_paths, p, nc.bundle(p, services,
                                                     declare={s: NOBODY for s in services}),
                            capsys)
        assert rc == 0, out
    try:
        yield int_paths, p, old, deploy
    finally:
        nc.teardown(int_paths, p)
        refs = [ref for svc in ("web", "side") for ref in subprocess.run(
            ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
             f"boxmunge.invalid/{p}/{svc}"], capture_output=True, text=True).stdout.split()]
        if refs:
            subprocess.run(["docker", "image", "rm", "-f", *refs], capture_output=True)


def _fd() -> FindingDisposition:
    return FindingDisposition(finding(CVE, pkg="busybox", fix=FIXED), Severity.CRITICAL, 0,
                              Severity.CRITICAL, Disposition.QUARANTINE, None, "")


def _autofix(paths, p):
    with project_lock(p, paths):
        return autofix_project_locked(paths, p, [_fd()], trigger="urgent",
                                      deadline=datetime.now(timezone.utc) + timedelta(minutes=30))


def test_patch_runs_pinned_and_is_recorded(deployed) -> None:
    paths, p, old, deploy = deployed
    deploy(None)
    (_cid, before), = _containers(p).values()
    outcome = _autofix(paths, p)
    assert outcome.ok, outcome.reason
    (pin,) = read_pins(paths, p)
    (record,) = read_records(paths, p)
    _cid, running = _containers(p)["web"]
    assert running == pin.image_id == record.patched_image_id != before
    assert record.base_digest == before and record.cves == (CVE,)
    (change,) = record.packages
    assert (change.name, change.before) == ("busybox", old) and change.after != old
    assert _inspect(pin.ref, "{{.Id}}") == pin.image_id


def _pin_side(paths, p: str, base: str) -> tuple[ImagePin, PatchRecord]:
    """Patch and pin the side service, as an earlier autofix would have."""
    with project_lock(p, paths):
        image = build_patched(p, "side", base, {"busybox": FIXED}, probe(base))
        pin = ImagePin("side", image.ref, image.image_id, "autofix")
        record = PatchRecord(p, "side", base, base, image.ref, image.image_id,
                             (PackageChange("busybox", "old", image.versions["busybox"]),),
                             ("CVE-2026-0001",), datetime.now(timezone.utc), "nightly")
        write_pins(paths, p, [pin])
        write_records(paths, p, [record])
        recreate_project(paths, p, ["compose.yml", "compose.boxmunge.yml"], component="test")
    return pin, record


def test_unhealthy_patch_rolls_back(deployed) -> None:
    """Healthy only on the old busybox: the patched image fails its check.
    The side service, pinned before, keeps its pin and patched image."""
    paths, p, old, deploy = deployed
    deploy(f"test \"$(apk list --installed busybox | cut -d' ' -f1)\" = busybox-{old}",
           side=True)
    before = _containers(p)["web"][1]
    side_pin, side_record = _pin_side(paths, p, before)
    side_container = _containers(p)["side"]
    assert side_container[1] == side_pin.image_id
    outcome = _autofix(paths, p)
    assert (outcome.ok, outcome.failed_step) == (False, "health"), outcome.reason
    assert outcome.rollback_problems == ()
    assert _containers(p)["web"][1] == before
    assert _containers(p)["side"][1] == side_pin.image_id
    assert read_pins(paths, p) == (side_pin,) and read_records(paths, p) == (side_record,)
    assert _inspect(side_pin.ref, "{{.Id}}") == side_pin.image_id
    tags = subprocess.run(["docker", "image", "ls", "--format", "{{.Tag}}",
                           f"boxmunge.invalid/{p}/web"],
                          capture_output=True, text=True, check=True).stdout.split()
    assert not [t for t in tags if t.startswith("autofix-")], tags
