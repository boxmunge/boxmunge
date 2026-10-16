# SPDX-License-Identifier: Apache-2.0
"""The CVE scan covers what is actually deployed (review findings 05, 06, 16).

A real Compose project is started with a custom container_name, replicas,
an included file, an extends service and two profile-gated services; then
image tags are moved the way a pull moves them. The scan must evaluate the
image each container actually runs, find services wherever the resolved
model defines them, count an expected service without a container as
unscanned, and skip a profile service only when it has no container.
Trivy is the only stub: it records the refs it is asked to scan.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from boxmunge.commands import security_scan_core
from boxmunge.commands.security_scan_core import scan_one_project
from boxmunge.commands.security_scan_inputs import (
    hardening_profile, load_project_meta, load_user_model,
)
from boxmunge.cve.kev import KevCatalog
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import (
    build_image, compose, container_image_ids, docker, image_id, tear_down,
)
from tests.test_commands.cve_helpers import make_box, scan_result, seed_quarantine

pytestmark = [pytest.mark.integration, skip_no_docker]

_SERVICES = ("web", "worker", "db", "ext", "dev", "tools", "gone")


@pytest.fixture(scope="module")
def deployed(tmp_path_factory):
    name = f"bminv-{uuid.uuid4().hex[:8]}"
    paths = make_box(tmp_path_factory.mktemp("box"), projects=(name,))
    project_dir = paths.project_dir(name)
    tags = {svc: f"{name}-img-{svc}:1" for svc in _SERVICES}
    ids = {svc: build_image(tags[svc], f"{name}-{svc}") for svc in _SERVICES}
    (project_dir / "db.yml").write_text(
        f"services:\n  db:\n    image: {tags['db']}\n    command: [sleep, '3600']\n")
    (project_dir / "base.yml").write_text(
        f"services:\n  base:\n    image: {tags['ext']}\n    command: [sleep, '3600']\n")
    (project_dir / "compose.yml").write_text(
        "include:\n  - db.yml\n"
        "services:\n"
        "  web:\n"
        f"    image: ${{WEB_IMAGE:-{tags['web']}}}\n"
        f"    container_name: {name}-custom-web\n"
        "    command: [sleep, '3600']\n"
        "  worker:\n"
        f"    image: {tags['worker']}\n"
        "    command: [sleep, '3600']\n"
        "    deploy:\n      replicas: 2\n"
        "  ext:\n"
        "    extends:\n      file: base.yml\n      service: base\n"
        "  dev:\n"
        f"    image: {tags['dev']}\n"
        "    profiles: [dev]\n"
        "  tools:\n"
        f"    image: {tags['tools']}\n"
        "    profiles: [tools]\n"
        "    command: [sleep, '3600']\n"
        "  gone:\n"
        f"    image: {tags['gone']}\n"
        "    command: [sleep, '3600']\n")
    extra_tags = [f"{name}-moved:1", f"{name}-worker-new:1"]
    try:
        compose(project_dir, name, "up", "-d")
        compose(project_dir, name, "--profile", "tools", "up", "-d", "tools")
        # A pull moves the web tag: the container still runs the old image.
        ids["moved"] = build_image(extra_tags[0], f"{name}-moved")
        docker("tag", extra_tags[0], tags["web"])
        # A third worker replica starts from a newer image than the first two.
        ids["worker-new"] = build_image(extra_tags[1], f"{name}-worker-new")
        docker("tag", extra_tags[1], tags["worker"])
        compose(project_dir, name, "up", "-d", "--no-recreate", "--scale", "worker=3",
                "worker")
        compose(project_dir, name, "rm", "-sf", "gone")
        assert container_image_ids(name, "web") == {ids["web"]}
        assert container_image_ids(name, "worker") == {ids["worker"], ids["worker-new"]}
        yield paths, name, ids
    finally:
        tear_down(project_dir, name, list(tags.values()) + extra_tags)


@pytest.fixture(scope="module")
def scan(deployed):
    paths, name, ids = deployed
    scanned: list[str] = []

    def fake_trivy(ref, timeout):
        scanned.append(ref)
        return scan_result(ref)

    mp = pytest.MonkeyPatch()
    mp.setattr(security_scan_core, "scan_image", fake_trivy)
    try:
        result = scan_one_project(
            paths, name, audit_only=True,
            kev=KevCatalog(cve_ids=frozenset(), fetched_at=datetime.now(timezone.utc)),
        )
    finally:
        mp.undo()
    return result, {_identity(ref) for ref in scanned}, ids


def _identity(ref: str) -> str:
    """The image ID a scanned ref names; a ref Docker cannot resolve stays as is."""
    try:
        return image_id(ref)
    except AssertionError:
        return ref


def test_custom_container_name_scans_the_running_image_not_the_moved_tag(scan):
    _, scanned, ids = scan
    assert ids["web"] in scanned
    assert ids["moved"] not in scanned


def test_every_replica_image_is_scanned(scan):
    _, scanned, ids = scan
    assert {ids["worker"], ids["worker-new"]} <= scanned


def test_included_and_extended_services_are_scanned(scan):
    _, scanned, ids = scan
    assert {ids["db"], ids["ext"]} <= scanned


def test_profile_service_without_container_is_inactive_not_scanned(scan):
    result, scanned, ids = scan
    assert ids["dev"] not in scanned
    assert "dev" not in result.unidentified_services


def test_profile_service_with_a_container_is_scanned(scan):
    _, scanned, ids = scan
    assert ids["tools"] in scanned


def test_expected_service_without_container_makes_the_scan_incomplete(scan):
    result, scanned, ids = scan
    assert ids["gone"] not in scanned
    assert result.unidentified_services == ("gone",)
    assert not result.complete


def test_hardening_counts_settings_from_included_files(tmp_path):
    """Policy inputs come from the resolved model too: a capability added in
    an included file weakens the project's hardening profile."""
    name = f"bminv-{uuid.uuid4().hex[:8]}"
    paths = make_box(tmp_path, projects=(name,))
    project_dir = paths.project_dir(name)
    (project_dir / "db.yml").write_text(
        "services:\n  db:\n    image: postgres:16-alpine\n    cap_add: [NET_ADMIN]\n")
    (project_dir / "compose.yml").write_text(
        "include:\n  - db.yml\nservices:\n  web:\n    image: nginx:1\n")
    meta = load_project_meta(paths, name)
    assert hardening_profile(meta, load_user_model(paths, name)).extra_caps_added


def test_quarantined_project_without_containers_scans_what_resume_starts(tmp_path):
    """Containers pruned, and the web tag moved since they were created: the
    resume re-scan checks the images `compose up` would start now, including
    the image Compose built for a build-only service."""
    name = f"bminv-{uuid.uuid4().hex[:8]}"
    paths = make_box(tmp_path, projects=(name,))
    project_dir = paths.project_dir(name)
    web, newer = f"{name}-img-web:1", f"{name}-img-web-new:1"
    build_image(web, f"{name}-web")
    (project_dir / "Dockerfile").write_text(f"FROM busybox:1.36\nLABEL bm.test={name}-app\n")
    (project_dir / "compose.yml").write_text(
        "services:\n"
        f"  web:\n    image: {web}\n    command: [sleep, '3600']\n"
        "  app:\n    build: .\n    command: [sleep, '3600']\n")
    try:
        compose(project_dir, name, "up", "-d", "--build")
        compose(project_dir, name, "down")
        new_id = build_image(newer, f"{name}-web-new")
        docker("tag", newer, web)
        seed_quarantine(paths, name)
        scanned: list[str] = []
        mp = pytest.MonkeyPatch()
        mp.setattr(security_scan_core, "scan_image",
                   lambda ref, timeout: scanned.append(ref) or scan_result(ref))
        try:
            result = scan_one_project(
                paths, name, audit_only=True,
                kev=KevCatalog(cve_ids=frozenset(), fetched_at=datetime.now(timezone.utc)),
            )
        finally:
            mp.undo()
        assert result.complete and result.stopped_reason == "quarantined"
        assert {_identity(ref) for ref in scanned} == {new_id, image_id(f"{name}-app")}
    finally:
        tear_down(project_dir, name, [web, newer, f"{name}-app"])
