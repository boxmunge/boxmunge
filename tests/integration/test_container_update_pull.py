# SPDX-License-Identifier: Apache-2.0
"""container-update on a project whose built service has a local image name.

Regression: a service declaring both `build: .` and `image: <local name>`
made `docker compose pull` ask Docker Hub for the local name, which failed
with "pull access denied" and recorded the update as failed every day. The
pull now skips buildable services (`--ignore-buildable`).
"""
from __future__ import annotations

import subprocess
import uuid

import pytest

from boxmunge.container_update import update_target
from boxmunge.container_update_targets import UpdateTarget
from boxmunge.docker import compose_down, compose_up
from boxmunge.paths import BoxPaths
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

_REGISTRY_IMAGE = "alpine:3.20"


@pytest.fixture
def mixed_project(tmp_path):
    name = f"myapp-{uuid.uuid4().hex[:8]}"
    local_image = f"{name}-web-local"
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.state, paths.deploy_state, paths.log_file.parent):
        d.mkdir(parents=True, exist_ok=True)
    project_dir = paths.project_dir(name)
    project_dir.mkdir(parents=True)
    (project_dir / "Dockerfile").write_text(
        f'FROM {_REGISTRY_IMAGE}\nCMD ["sleep", "3600"]\n')
    (project_dir / "compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    build: .\n"
        f"    image: {local_image}\n"
        "  cache:\n"
        f"    image: {_REGISTRY_IMAGE}\n"
        '    command: ["sleep", "3600"]\n')
    compose_up(project_dir, project_name=name)
    yield paths, name, project_dir
    compose_down(project_dir, project_name=name)
    subprocess.run(["docker", "image", "rm", "-f", local_image],
                   capture_output=True, check=False)


def test_built_service_with_local_image_name_is_not_pulled(mixed_project):
    paths, name, project_dir = mixed_project
    # The failure this guards against is real: a plain pull asks a registry
    # for the local name.
    plain = subprocess.run(["docker", "compose", "-p", name, "pull"], cwd=project_dir,
                           capture_output=True, text=True, check=False)
    assert plain.returncode != 0
    assert "pull access denied" in plain.stderr

    target = UpdateTarget(name=name, project_dir=project_dir, compose_files=["compose.yml"],
                          strategy="leave_broken", has_backup=False)
    result = update_target(paths, target)
    assert result["status"] == "no_change", result["reason"]
