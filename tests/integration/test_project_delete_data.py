# SPDX-License-Identifier: Apache-2.0
"""project-delete removes data a container wrote as its own user.

On Linux the container's files belong to root or the service's uid, which
the user running boxmunge cannot remove; the data helper empties them
first. (Docker Desktop shows bind-mounted files as the host user, so there
the helper has nothing to do; CI on Linux is the authoritative run.)
"""
from __future__ import annotations

import subprocess
import uuid

import pytest

from boxmunge.commands.project_delete_cmd import run_project_delete
from boxmunge.project_registry import add_project
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import BUSYBOX, ensure_busybox

pytestmark = [pytest.mark.integration, skip_no_docker, pytest.mark.usefixtures("helper_image")]


def test_container_owned_data_is_deleted(int_paths) -> None:
    ensure_busybox()
    name = f"bmdel{uuid.uuid4().hex[:8]}"
    pdir = int_paths.project_dir(name)
    pdir.mkdir(parents=True)
    add_project(name, int_paths)
    subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{pdir}:/p", BUSYBOX,
                    "sh", "-c", "mkdir -p /p/pgdata/base && echo x > /p/pgdata/base/f && "
                    "chown -R 999:999 /p/pgdata && chmod -R go-rwx /p/pgdata"],
                   check=True, capture_output=True)
    assert run_project_delete(name, int_paths, yes=True) == 0
    assert not pdir.exists()
