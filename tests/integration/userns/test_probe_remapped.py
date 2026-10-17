"""The image probe on a remapped daemon: the helper sees container ids."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge import data_helper
from boxmunge.image_probe import probe_dir
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND

DOCKERFILE = (f"FROM {BUSYBOX}\nRUN mkdir /data /vol && chown 1000:1001 /data && "
              f"chmod 750 /data && chown 70:70 /vol\nVOLUME /vol\n")


@pytest.fixture(scope="module")
def probe_image(remapped_daemon):
    tag = "boxmunge-probe-test:remapped"
    subprocess.run(["docker", "build", "-q", "-t", tag, "-"], input=DOCKERFILE, text=True,
                   check=True, capture_output=True)
    image_id = subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}", tag], check=True,
                              capture_output=True, text=True).stdout.strip()
    subprocess.run(["docker", "tag", BUSYBOX, data_helper.HELPER_IMAGE], check=True)
    yield image_id, remapped_daemon
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)


def _volumes() -> set[str]:
    return set(subprocess.run(["docker", "volume", "ls", "-q"], check=True,
                              capture_output=True, text=True).stdout.split())


def test_remapped_probe_translates_and_leaves_no_volume(probe_image) -> None:
    image_id, _s = probe_image
    before = _volumes()
    data = probe_dir(image_id, "/data")
    assert (data.uid, data.gid, data.mode) == (1000, 1001, 0o750)
    assert probe_dir(image_id, "/vol").uid == 70
    assert probe_dir(image_id, "/absent") is None
    assert _volumes() == before
