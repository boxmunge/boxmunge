# SPDX-License-Identifier: Apache-2.0
"""deploy_storage on a remapped daemon: the user's ids land as S+N on the host."""
from __future__ import annotations

import os
import subprocess

import pytest

from boxmunge import data_helper
from boxmunge.commands import deploy_storage as ds
from boxmunge.release_target import production_target
from boxmunge.run_as import ServiceUser, write_users
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND


@pytest.fixture(scope="module")
def helper_image(remapped_daemon):
    subprocess.run(["docker", "tag", BUSYBOX, data_helper.HELPER_IMAGE], check=True)
    yield remapped_daemon
    subprocess.run(["docker", "image", "rm", data_helper.HELPER_IMAGE], capture_output=True)


def test_rw_source_and_fresh_volume_belong_to_the_user(dind_record, helper_image,
                                                        monkeypatch) -> None:
    s, paths = helper_image, dind_record
    project_dir = paths.project_dir("st")
    project_dir.mkdir(parents=True)
    services = {"app": {"image": BUSYBOX, "volumes": [
        {"type": "bind", "source": str(project_dir / "data" / "uploads"), "target": "/u"},
        {"type": "volume", "source": "cache", "target": "/cache"}]}}
    monkeypatch.setattr(ds, "resolved_services", lambda target: ({}, services))
    write_users(paths, "st", {"app": ServiceUser("10001:10001", "manifest")})
    try:
        ds.prepare_storage(paths, production_target(paths, "st"))
        assert os.lstat(project_dir / "data" / "uploads").st_uid == s + 10001
        assert os.lstat(project_dir / "data").st_uid == os.geteuid()
        for _ in range(2):  # busybox has no /cache, so no create re-copies an owner
            subprocess.run(["docker", "run", "--rm", "--user", "10001:10001", "-v",
                            "st_cache:/cache", BUSYBOX, "touch", "/cache/x"], check=True)
        mount = subprocess.run(["docker", "volume", "inspect", "-f", "{{.Mountpoint}}",
                                "st_cache"], check=True, capture_output=True,
                               text=True).stdout.strip()
        assert os.lstat(mount).st_uid == s + 10001
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", "st_cache"], capture_output=True)
