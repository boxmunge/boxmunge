# SPDX-License-Identifier: Apache-2.0
"""Every running service is scanned, built or pulled, listed in the manifest
or not (audit B-10). Docker lookups are stubbed; the scan code is real."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.commands import security_actions, security_resume, security_scan_core
from boxmunge.commands import security_scan_inputs as inputs
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.commands.security_scan_inputs import identify_images
from boxmunge.cve.quarantine import is_quarantined
from tests.test_commands.cve_helpers import Docker, Pushover, make_box, scan_result, seed_quarantine

_WEB_ID = "sha256:" + "1" * 64
_BUILT_ID = "sha256:" + "2" * 64
_DIGEST = "sha256:" + "9" * 64


@pytest.fixture
def daemon(monkeypatch):
    """A fake Docker daemon: containers → (repo digest, image id); local images."""
    state = {"containers": {}, "images": {}}
    monkeypatch.setattr(inputs, "container_image_digest",
                        lambda c: state["containers"].get(c, (None, None))[0])
    monkeypatch.setattr(inputs, "container_image_id",
                        lambda c: state["containers"].get(c, (None, None))[1])
    monkeypatch.setattr(inputs, "local_image_id", lambda r: state["images"].get(r))
    return state


def _manifest(*services):
    return {"services": {s: {} for s in services}}


def _targets(inventory):
    return {t.service: t.image_ref for t in inventory.targets}


def test_build_only_service_is_scanned_by_image_id(daemon):
    daemon["containers"]["demo-web-1"] = (None, _WEB_ID)
    inv = identify_images(_manifest("web"), {"services": {"web": {"build": "."}}}, "demo")
    assert _targets(inv) == {"web": _WEB_ID} and inv.unidentified == []


def test_registry_digest_is_preferred_and_keeps_a_registry_port(daemon):
    daemon["containers"]["demo-web-1"] = (_DIGEST, _WEB_ID)
    compose = {"services": {"web": {"image": "registry.example.com:5000/team/app:1.2"}}}
    inv = identify_images(_manifest("web"), compose, "demo")
    assert _targets(inv) == {"web": f"registry.example.com:5000/team/app@{_DIGEST}"}


def test_compose_only_services_are_scanned(daemon):
    """The template's db is compose-only; it runs, so it is scanned."""
    daemon["containers"]["demo-web-1"] = (None, _WEB_ID)
    compose = {"services": {"web": {"build": "."}, "db": {"image": "postgres:16-alpine"},
                            "cache": {"image": "redis:7"}}}
    inv = identify_images(_manifest("web"), compose, "demo")
    assert _targets(inv) == {"web": _WEB_ID, "db": "postgres:16-alpine", "cache": "redis:7"}


def test_built_image_is_found_when_the_container_is_gone(daemon):
    daemon["images"]["demo-web"] = _BUILT_ID
    inv = identify_images(_manifest("web"), {"services": {"web": {"build": "."}}}, "demo")
    assert _targets(inv) == {"web": _BUILT_ID}


def test_never_built_service_is_unidentified(daemon):
    inv = identify_images(_manifest("web"), {"services": {"web": {"build": "."}}}, "demo")
    assert inv.targets == [] and inv.unidentified == ["web"]


def test_profile_service_that_is_not_running_is_not_a_failure(daemon):
    compose = {"services": {"migrate": {"build": ".", "profiles": ["tools"]}}}
    inv = identify_images(_manifest(), compose, "demo")
    assert inv.targets == [] and inv.unidentified == [] and inv.not_started == ["migrate"]


@pytest.fixture
def build_only_box(tmp_path, monkeypatch, daemon):
    """'demo': manifest service web is build-only; compose adds db."""
    paths = make_box(tmp_path, images={})
    compose_path = paths.project_dir("demo") / "compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    compose["services"]["db"] = {"image": "postgres:16-alpine"}
    compose_path.write_text(yaml.safe_dump(compose))
    daemon["containers"]["demo-web-1"] = (None, _WEB_ID)
    daemon["containers"]["demo-db-1"] = (_DIGEST, "sha256:" + "3" * 64)
    scanned: list[str] = []

    def scan(ref, timeout):
        scanned.append(ref)
        return scan_result(ref)

    monkeypatch.setattr(security_scan_core, "scan_image", scan)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_resume, "refresh_db", lambda: None)
    paths.scanned = scanned
    return paths


def test_nightly_scan_of_a_build_only_project_is_complete(build_only_box, monkeypatch):
    pushover = Pushover(monkeypatch, build_only_box)
    assert cmd_security_scan([], build_only_box) == 0
    assert build_only_box.scanned == [_WEB_ID, f"postgres@{_DIGEST}"]
    assert [t for t in pushover.titles() if "scan incomplete" in t] == []


def test_resume_lifts_a_build_only_project(build_only_box, monkeypatch):
    seed_quarantine(build_only_box)
    Docker(monkeypatch)
    monkeypatch.setattr(security_resume, "prepare_caddy_config", lambda p, m: None)
    monkeypatch.setattr(security_resume, "prepare_compose_override",
                        lambda p, m, component=None: None)
    monkeypatch.setattr(security_resume, "run_smoke", lambda p, paths_: (True, "ok"))
    assert cmd_security_resume(["demo"], build_only_box) == 0
    assert not is_quarantined("demo", build_only_box)


def test_docker_image_id_primitives(monkeypatch):
    import subprocess

    from boxmunge import docker

    outputs = {"inspect": _WEB_ID + "\n", "image": "<no value>\n"}

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, outputs[cmd[1]], "")

    monkeypatch.setattr(docker, "_run", fake_run)
    assert docker.container_image_id("demo-web-1") == _WEB_ID
    assert docker.local_image_id("demo-web") is None
