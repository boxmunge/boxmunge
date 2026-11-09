# SPDX-License-Identifier: Apache-2.0
"""A project deployed by boxmunge 0.10.1 and stopped across the upgrade to
0.11 comes back on its deployed files, with no deploy, on a real daemon.

0.10.1 mounted production's smoke scripts from ./.releases/live-scripts and
kept no record of bind sources; 0.11 mounts ./boxmunge-scripts. The upgrade
used to leave a quarantined or paused project's 0.10.1 overlay in place and
record the bind sources from it, so the lift (and resume), which regenerate
the overlay, were refused: "bind source boxmunge-scripts was not mounted
when the project was last deployed". The upgrade now regenerates such a
project's overlay and records the bind sources from it, as for a running
project, keeping the maintenance page and starting nothing.

Real files, `docker compose config`, containers and bind mounts. Trivy,
Caddy and Pushover are stubbed. The image half is provided by the fixture:
the 0.10.1 build is also tagged with its platform name
(boxmunge.invalid/<project>/web), which the overlay starts it by.
"""
from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands import quarantine_lift, security_scan_core
from boxmunge.commands.resume_cmd import resume_locked
from boxmunge.commands.security_resume import security_resume_locked
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_guard import check_start
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.docker import compose_stop, compose_up
from boxmunge.manifest import CURRENT_SCHEMA_VERSION, load_manifest
from boxmunge.pause import is_paused, write_paused_state
from boxmunge.upgrade_exclusions import apply_projects
from tests.integration.conftest import skip_no_docker
from tests.integration.nonroot_cases import BUSYBOX
from tests.test_commands.cve_helpers import (
    CRIT, Pushover, make_box, render_site, scan_result, seed_quarantine,
)

pytestmark = [pytest.mark.integration, skip_no_docker]

FILES = ["compose.yml", "compose.boxmunge.yml"]

# What 0.10.1's generator wrote for production's smoke scripts: a copy
# under .releases/, in the short syntax.
_OVERLAY_0101 = """\
services:
  web:
    volumes:
    - ./.releases/live-scripts:/boxmunge-scripts:ro
"""


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _container(p: str) -> dict:
    return json.loads(_docker("container", "inspect", f"{p}-web-1"))[0]


def _mounts(p: str) -> dict[str, str]:
    return {m["Destination"]: m["Source"] for m in _container(p)["Mounts"]}


def _sources(paths, p: str) -> dict[str, str]:
    return json.loads(paths.project_bind_record(p).read_text())["sources"]


def _write_0101_project(paths, p: str) -> None:
    """The project as 0.10.1 deployed it: release files in the project dir,
    no release tree under .releases/ but the live-scripts copy, the 0.10.1
    overlay, and no bind-source record."""
    pdir = paths.project_dir(p)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.safe_dump({
        "schema_version": CURRENT_SCHEMA_VERSION, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle", "project": p, "hosts": [f"{p}.example.com"],
        "security": {"posture": "balanced"},
        "services": {"web": {"port": 3000, "internal": True,
                             "smoke": "boxmunge-scripts/smoke.sh"}},
    }))
    (pdir / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "build": ".", "image": p, "volumes": ["./data:/app/data"]}}}))
    (pdir / "Dockerfile").write_text(f'FROM {BUSYBOX}\nCMD ["sleep", "infinity"]\n')
    (pdir / "compose.boxmunge.yml").write_text(_OVERLAY_0101)
    for scripts in (pdir / "boxmunge-scripts", pdir / ".releases" / "live-scripts"):
        scripts.mkdir(parents=True)
        (scripts / "smoke.sh").write_text("#!/bin/sh\nexit 0\n")
        (scripts / "smoke.sh").chmod(0o755)
    (pdir / "data").mkdir()
    (paths.state / "projects.txt").write_text(f"{p}\n")


@pytest.fixture
def box(tmp_path, monkeypatch):
    """(paths, project, image ID): deployed and started as 0.10.1 did, then
    stopped. Every image scan finds one critical finding that is not
    KEV-listed, which under balanced no longer quarantines."""
    p = f"bmql{uuid.uuid4().hex[:8]}"
    paths = make_box(tmp_path, projects=())
    _write_0101_project(paths, p)
    pdir = paths.project_dir(p)
    try:
        compose_up(pdir, compose_files=FILES, project_name=p)
        compose_stop(pdir, compose_files=FILES, project_name=p)
        image_id = _container(p)["Image"]
        _docker("tag", image_id, f"boxmunge.invalid/{p}/web")
        monkeypatch.setattr(security_scan_core, "scan_image",
                            lambda ref, timeout: scan_result(ref, [CRIT]))
        monkeypatch.setattr(quarantine_lift, "prepare_caddy_config", render_site)
        Pushover(monkeypatch, paths)
        with patch("boxmunge.cve.quarantine.caddy_reload") as reload:
            paths.caddy_reload = reload
            yield paths, p, image_id
    finally:
        subprocess.run(["docker", "compose", "-p", p, "down", "-v", "--rmi", "local",
                        "-t", "0"], cwd=pdir, capture_output=True, check=False)
        subprocess.run(["docker", "image", "rm", "-f", p, f"boxmunge.invalid/{p}/web"],
                       capture_output=True, check=False)


def _kev() -> KevCatalog:
    return KevCatalog(frozenset(), datetime.now(timezone.utc))


def _upgrade(paths):
    """The upgrade's migrate-and-regenerate step, as --apply runs it."""
    return apply_projects(paths)[1]


def _back_on_the_0_11_overlay(paths, p: str, image_id: str) -> None:
    """Running the image it was stopped on, with 0.11's smoke mount, and
    0.10.1's copy of the scripts swept."""
    pdir = paths.project_dir(p)
    assert _container(p)["State"]["Running"]
    assert _container(p)["Image"] == image_id
    assert _mounts(p)["/boxmunge-scripts"] == str(pdir / "boxmunge-scripts")
    assert not (pdir / ".releases" / "live-scripts").exists()
    assert _sources(paths, p) == {"boxmunge-scripts": "dir", "data": "dir"}


def test_the_upgrade_records_the_overlay_it_regenerates_and_starts_nothing(box) -> None:
    paths, p, _image_id = box
    seed_quarantine(paths, p)
    regen = _upgrade(paths)
    assert regen.refused == {} and p in regen.processed
    overlay = yaml.safe_load(paths.project_compose_override(p).read_text())
    assert [v["source"] for v in overlay["services"]["web"]["volumes"]] == ["./boxmunge-scripts"]
    assert _sources(paths, p) == {"boxmunge-scripts": "dir", "data": "dir"}
    site = paths.project_caddy_site(p).read_text()
    assert "status 503" in site and "reverse_proxy" not in site
    assert not _container(p)["State"]["Running"]
    assert is_quarantined(p, paths)


def test_lift_scan_after_the_upgrade_brings_it_back(box) -> None:
    """The sequence on an upgraded box: quarantined under 0.10.1, upgraded,
    then the fleet scan lifts the quarantine balanced no longer takes."""
    paths, p, image_id = box
    seed_quarantine(paths, p)
    _upgrade(paths)
    scan = scan_one_project(paths, p, in_grace=False, kev=_kev())
    assert scan.complete
    assert not is_quarantined(p, paths)
    _back_on_the_0_11_overlay(paths, p, image_id)


def test_security_resume_after_the_upgrade_brings_it_back(box, capsys) -> None:
    paths, p, image_id = box
    seed_quarantine(paths, p)
    _upgrade(paths)
    rc = security_resume_locked(paths, p)
    out = capsys.readouterr()
    assert rc == 0, out.err
    assert "Smoke test: OK" in out.out
    assert not is_quarantined(p, paths)
    _back_on_the_0_11_overlay(paths, p, image_id)


def test_the_upgrade_repairs_what_a_failed_lift_left(box) -> None:
    """What the 0.11.2 upgrade and its failed lift left on the box: a record
    taken from the 0.10.1 overlay, and the regenerated overlay on disk. The
    next upgrade records the overlay that will start, and the scan lifts."""
    paths, p, image_id = box
    seed_quarantine(paths, p)
    check_start(paths, p, component="upgrade", compose_files=FILES, record=True)
    prepare_compose_override(paths, load_manifest(paths.project_manifest(p)))
    assert _sources(paths, p) == {".releases/live-scripts": "dir", "data": "dir"}

    _upgrade(paths)
    scan_one_project(paths, p, in_grace=False, kev=_kev())
    assert not is_quarantined(p, paths)
    _back_on_the_0_11_overlay(paths, p, image_id)


def test_a_refused_lift_leaves_the_maintenance_page_live(box) -> None:
    """The lift checks the overlay it is about to start before it touches
    Caddy. Here the record is the one the 0.11.2 upgrade took from the
    0.10.1 overlay, with no upgrade since to replace it."""
    paths, p, _image_id = box
    seed_quarantine(paths, p)
    paths.project_caddy_site(p).write_text("# maintenance page\n")
    check_start(paths, p, component="upgrade", compose_files=FILES, record=True)
    with pytest.raises(RuntimeError, match="bind source boxmunge-scripts was not mounted"):
        scan_one_project(paths, p, in_grace=False, kev=_kev())
    assert is_quarantined(p, paths)
    paths.caddy_reload.assert_not_called()
    assert paths.project_caddy_site(p).read_text() == "# maintenance page\n"
    assert not _container(p)["State"]["Running"]


def test_resume_after_the_upgrade_leaves_a_startable_project(box) -> None:
    """Paused across the upgrade: `resume` starts it on the overlay the
    record describes, so the next start (a container update, a lift) is
    not refused either."""
    paths, p, _image_id = box
    write_paused_state(p, paths)
    _upgrade(paths)
    with patch("boxmunge.commands.resume_cmd.prepare_caddy_config", render_site), \
         patch("boxmunge.commands.resume_cmd.caddy_reload"):
        rc, smoke_failure = resume_locked(p, paths, skip_security_checks=True)
    assert rc == 0 and smoke_failure is None
    assert not is_paused(p, paths)
    pdir = paths.project_dir(p)
    assert _mounts(p)["/boxmunge-scripts"] == str(pdir / "boxmunge-scripts")
    check_start(paths, p, component="container-update", compose_files=FILES)


def test_the_upgrade_still_refuses_a_bind_source_it_cannot_record(box) -> None:
    """Recording at the upgrade runs the start checks: a bind source that is
    now a symlink is refused, nothing is recorded, and the lift is refused
    until a deploy records the project."""
    paths, p, _image_id = box
    seed_quarantine(paths, p)
    pdir = paths.project_dir(p)
    (pdir / "data").rename(pdir / "elsewhere")
    os.symlink("elsewhere", pdir / "data")
    regen = _upgrade(paths)
    assert "data is a symlink" in regen.refused[p]
    assert not paths.project_bind_record(p).exists()
    with pytest.raises(RuntimeError, match="no record of the bind sources"):
        scan_one_project(paths, p, in_grace=False, kev=_kev())
    assert is_quarantined(p, paths)
    paths.caddy_reload.assert_not_called()
    assert not _container(p)["State"]["Running"]
