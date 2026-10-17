"""The layer scan on real `docker save` output of the prior store (the
containerd store saves gzip blobs in an OCI layout; overlay2 plain tars)."""
from __future__ import annotations

import subprocess

from boxmunge.docker_run import docker_env
from boxmunge.userns.layers import image_high_ids
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND
TAG = "boxmunge.invalid/dind/highids:1"


def _docker(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], input=stdin, env=docker_env(), check=True,
                          capture_output=True, text=True)


def test_an_image_with_a_high_id_is_found_and_busybox_is_clean(tmp_path) -> None:
    _docker("pull", "-q", BUSYBOX)
    assert image_high_ids(BUSYBOX) == []
    dockerfile = f"FROM {BUSYBOX}\nRUN touch /big && chown 70000:70000 /big\n"
    _docker("build", "-q", "-t", TAG, "-", stdin=dockerfile)
    try:
        assert image_high_ids(TAG) == ["big (70000:70000)"]
    finally:
        _docker("image", "rm", TAG)
