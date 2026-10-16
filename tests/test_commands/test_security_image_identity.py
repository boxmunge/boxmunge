# SPDX-License-Identifier: Apache-2.0
"""Every deployed container is scanned by the image it actually runs: built
or pulled, listed in the manifest or not (audit B-10), whatever its name
(review finding 05). Containers come from conftest's fake_containers; the
scan code is real. tests/integration/test_scan_inventory.py covers the same
rules against real Compose and Docker."""
from __future__ import annotations

import pytest
import yaml

from boxmunge.commands import security_actions, security_resume, security_scan_core
from boxmunge.commands.security_actions import cmd_security_scan
from boxmunge.commands.security_resume import cmd_security_resume
from boxmunge.commands.security_scan_inputs import identify_images
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.deployed_inventory import load_deployed_inventory
from boxmunge.docker_containers import LocalImage
from tests.test_commands.cve_helpers import Docker, Pushover, make_box, scan_result, seed_quarantine

_WEB_ID = "sha256:" + "1" * 64
_NEW_ID = "sha256:" + "2" * 64
_DB_ID = "sha256:" + "3" * 64
_DIGEST = "sha256:" + "9" * 64


@pytest.fixture
def running(fake_containers):
    """``running(service, image_id, ...)`` adds a container to project demo;
    demo starts with none."""
    fake_containers.remove("demo")
    return lambda service, image_id, **kw: fake_containers.run("demo", service, image_id, **kw)


def _identify(tmp_path, compose, *manifest_services):
    (tmp_path / "compose.yml").write_text(yaml.safe_dump(compose))
    deployed = load_deployed_inventory(tmp_path, ["compose.yml"], "demo")
    return identify_images({"services": {s: {} for s in manifest_services}}, deployed)


def _targets(inventory):
    return [(t.service, t.image_ref) for t in inventory.targets]


def test_build_only_service_is_scanned_by_image_id(tmp_path, running):
    running("web", _WEB_ID)
    inv = _identify(tmp_path, {"services": {"web": {"build": "."}}}, "web")
    assert _targets(inv) == [("web", _WEB_ID)] and inv.unidentified == {}


def test_registry_digest_is_preferred_and_keeps_a_registry_port(tmp_path, running):
    running("web", _WEB_ID, repo_digests=(f"registry.example.com:5000/team/app@{_DIGEST}",))
    compose = {"services": {"web": {"image": "registry.example.com:5000/team/app:1.2"}}}
    inv = _identify(tmp_path, compose, "web")
    assert _targets(inv) == [("web", f"registry.example.com:5000/team/app@{_DIGEST}")]


def test_custom_container_name_is_found_by_its_labels(tmp_path, running):
    running("web", _WEB_ID, name="my-custom-web")
    compose = {"services": {"web": {"image": "nginx:1", "container_name": "my-custom-web"}}}
    assert _targets(_identify(tmp_path, compose, "web")) == [("web", _WEB_ID)]


def test_every_replica_image_is_scanned_once(tmp_path, running):
    running("web", _WEB_ID)
    running("web", _WEB_ID)
    running("web", _NEW_ID)
    inv = _identify(tmp_path, {"services": {"web": {"image": "nginx:1"}}}, "web")
    assert _targets(inv) == [("web", _WEB_ID), ("web", _NEW_ID)]


def test_compose_only_services_are_scanned(tmp_path, running):
    """The template's db is compose-only; it runs, so it is scanned."""
    running("web", _WEB_ID)
    running("db", _DB_ID)
    compose = {"services": {"web": {"build": "."}, "db": {"image": "postgres:16-alpine"}}}
    assert _targets(_identify(tmp_path, compose, "web")) == [("web", _WEB_ID), ("db", _DB_ID)]


def test_service_without_container_is_unidentified_not_scanned_by_tag(tmp_path, running):
    """The tag names whatever was pulled last, not what is deployed."""
    inv = _identify(tmp_path, {"services": {"web": {"image": "nginx:1"}}}, "web")
    assert inv.targets == [] and list(inv.unidentified) == ["web"]


def test_manifest_service_missing_from_the_model_is_unidentified(tmp_path, running):
    inv = _identify(tmp_path, {"services": {}}, "web")
    assert list(inv.unidentified) == ["web"]


def test_profile_service_without_container_is_inactive(tmp_path, running):
    compose = {"services": {"migrate": {"image": "tools:1", "profiles": ["tools"]}}}
    inv = _identify(tmp_path, compose)
    assert inv.targets == [] and inv.unidentified == {} and inv.not_started == ["migrate"]


def test_service_scaled_to_zero_is_inactive(tmp_path, running):
    compose = {"services": {"a": {"image": "a:1", "deploy": {"replicas": 0}},
                            "b": {"image": "b:1", "scale": 0}}}
    inv = _identify(tmp_path, compose)
    assert inv.unidentified == {} and inv.not_started == ["a", "b"]


def test_profile_service_with_a_container_is_scanned(tmp_path, running):
    running("migrate", _WEB_ID)
    compose = {"services": {"migrate": {"image": "tools:1", "profiles": ["tools"]}}}
    inv = _identify(tmp_path, compose)
    assert _targets(inv) == [("migrate", _WEB_ID)] and inv.not_started == []


def test_container_of_a_removed_service_is_still_scanned(tmp_path, running):
    running("old", _WEB_ID)
    assert _targets(_identify(tmp_path, {"services": {}})) == [("old", _WEB_ID)]


@pytest.fixture
def build_only_box(tmp_path, monkeypatch, fake_containers):
    """'demo': manifest service web is build-only; compose adds db."""
    paths = make_box(tmp_path, images={})
    compose_path = paths.project_dir("demo") / "compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    compose["services"]["db"] = {"image": "postgres:16-alpine"}
    compose_path.write_text(yaml.safe_dump(compose))
    from tests.deploy_helpers import mark_deployed
    mark_deployed(paths, "demo")
    fake_containers.run("demo", "web", _WEB_ID)
    fake_containers.run("demo", "db", _DB_ID, repo_digests=(f"postgres@{_DIGEST}",))
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


def test_resume_lifts_a_build_only_project(build_only_box, monkeypatch, fake_containers):
    """Quarantined, so the re-scan checks what the lift starts: the build tag."""
    fake_containers.images["demo-web"] = LocalImage(image_id=_WEB_ID, repo_digests=())
    seed_quarantine(build_only_box)
    Docker(monkeypatch)
    monkeypatch.setattr(security_resume, "prepare_caddy_config", lambda p, m: None)
    monkeypatch.setattr(security_resume, "prepare_compose_override",
                        lambda p, m, component=None: None)
    monkeypatch.setattr(security_resume, "run_smoke", lambda p, paths_: (True, "ok"))
    assert cmd_security_resume(["demo"], build_only_box) == 0
    assert not is_quarantined("demo", build_only_box)
