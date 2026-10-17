# SPDX-License-Identifier: Apache-2.0
"""The system container from system/compose.yml under a remapped daemon: in
the host user namespace it reads the root:deploy 0640 backup key and writes
as deploy; a remapped copy can do neither, and connect() refuses it."""
from __future__ import annotations

import os
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

import boxmunge.system_container as sc
from boxmunge import data_helper
from boxmunge.docker_run import docker_env
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND

SYSTEM_COMPOSE = Path(__file__).resolve().parents[3] / "system" / "compose.yml"
DEPLOY = 1000
KEY = "AGE-SECRET-KEY-1DINDTEST\n"


@pytest.fixture(scope="module")
def system_image(remapped_daemon):
    # busybox stands in for the system image: these tests need only sh, cat
    # and sleep. It carries the system image's name, so compose uses it as is.
    subprocess.run(["docker", "tag", BUSYBOX, data_helper.HELPER_IMAGE], check=True)
    yield remapped_daemon
    subprocess.run(["docker", "image", "rm", data_helper.HELPER_IMAGE], check=True,
                   capture_output=True)


@contextmanager
def _system(paths, tmp_path: Path, extra: str):
    """system/compose.yml started for `paths` as install.sh starts it."""
    os.chown(paths.projects, DEPLOY, DEPLOY)
    paths.rclone_config_dir.mkdir()
    paths.backup_key.write_text(KEY)
    os.chown(paths.backup_key, 0, DEPLOY)
    os.chmod(paths.backup_key, 0o640)
    override = tmp_path / "override.yml"
    override.write_text("services:\n  system:\n    entrypoint: [sleep, '3600']\n" + extra)
    cmd = ["docker", "compose", "-p", "bmsys-dind", "-f", str(SYSTEM_COMPOSE),
           "-f", str(override)]
    env = {**docker_env(), "BOXMUNGE_UID": str(DEPLOY), "BOXMUNGE_GID": str(DEPLOY),
           "BOXMUNGE_CONFIG": str(paths.config), "BOXMUNGE_PROJECTS": str(paths.projects)}
    try:
        up = subprocess.run([*cmd, "up", "-d", "--no-build", "--pull", "never", "--wait"],
                            env=env, capture_output=True, text=True)
        assert up.returncode == 0, up.stderr
        yield
    finally:
        down = subprocess.run([*cmd, "down"], env=env, capture_output=True, text=True)
        if down.returncode != 0:
            print(f"compose down failed: {down.stderr}")


def test_host_namespace_reads_the_key_and_writes_as_deploy(
        system_image, dind_record, tmp_path) -> None:
    with _system(dind_record, tmp_path, ""):
        tools = sc.connect(dind_record)
        assert tools.run(["cat", tools.path(dind_record.backup_key)]).stdout == KEY
        tools.run(["sh", "-c", "echo x > /projects/written"])
        st = (dind_record.projects / "written").stat()
        assert (st.st_uid, st.st_gid) == (DEPLOY, DEPLOY)


def test_a_remapped_system_container_is_refused(system_image, dind_record, tmp_path) -> None:
    with _system(dind_record, tmp_path, "    userns_mode: !reset null\n"):
        with pytest.raises(sc.SystemContainerError, match="remapped user namespace"):
            sc.connect(dind_record)
        for probe in ("cat /config/backup.key", "echo x > /projects/written"):
            run = subprocess.run(["docker", "exec", sc.CONTAINER_NAME, "sh", "-c", probe],
                                 capture_output=True, text=True, env=docker_env())
            assert run.returncode != 0 and "Permission denied" in run.stderr, probe
