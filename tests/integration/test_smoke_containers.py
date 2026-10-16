# SPDX-License-Identifier: Apache-2.0
"""Smoke tests run in the containers Compose labels as the service's, so a
custom container_name and every running replica are tested."""
from __future__ import annotations

import uuid

import pytest

from boxmunge.commands.check import run_smoke_in_container
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import BUSYBOX, compose, docker, ensure_busybox, tear_down

pytestmark = [pytest.mark.integration, skip_no_docker]


@pytest.fixture
def project(tmp_path):
    ensure_busybox()
    name = f"bmsmoke-{uuid.uuid4().hex[:8]}"
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "smoke.sh").write_text(
        "test ! -e /tmp/broken || { echo \"$(hostname) broken\" >&2; exit 1; }\n")
    common = ("    command: [sleep, '3600']\n"
              "    volumes: ['./scripts:/boxmunge-scripts:ro']\n")
    (tmp_path / "compose.yml").write_text(
        "services:\n"
        f"  web:\n    image: {BUSYBOX}\n    container_name: {name}-custom\n{common}"
        f"  worker:\n    image: {BUSYBOX}\n    deploy:\n      replicas: 2\n{common}")
    compose(tmp_path, name, "up", "-d")
    manifest = {"project": name, "services": {
        s: {"port": 80, "routes": [], "smoke": "boxmunge-scripts/smoke.sh"}
        for s in ("web", "worker")}}
    yield tmp_path, name, manifest
    tear_down(tmp_path, name, [])


def test_custom_name_and_replicas_pass(project):
    project_dir, _, manifest = project
    assert run_smoke_in_container(project_dir, manifest, ["compose.yml"]).status == "ok"


def test_a_failing_second_replica_is_caught(project):
    project_dir, name, manifest = project
    docker("exec", f"{name}-worker-2", "touch", "/tmp/broken")
    result = run_smoke_in_container(project_dir, manifest, ["compose.yml"])
    assert result.status == "warning"
    assert "broken" in result.message
