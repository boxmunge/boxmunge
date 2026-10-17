"""The image probe on a real (unremapped) daemon: owners read from an image
mount, without archiving anything and leaving nothing behind."""
from __future__ import annotations

import subprocess
import time
import uuid

import pytest

from boxmunge.image_probe import probe_dir
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import build_image

pytestmark = [pytest.mark.integration, skip_no_docker]

DOCKERFILE = ("RUN mkdir /data /vol && chown 1000:1001 /data && chmod 750 /data && "
              "chown 70:70 /vol && truncate -s 4G /data/big && ln -s /etc /link\nVOLUME /vol\n")


@pytest.fixture(scope="module")
def probe_image():
    tag = f"boxmunge-probe-test:{uuid.uuid4().hex[:8]}"
    yield build_image(tag, "probe", DOCKERFILE)
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)


def _volumes() -> set[str]:
    return set(subprocess.run(["docker", "volume", "ls", "-q"], check=True,
                              capture_output=True, text=True).stdout.split())


def test_probe_reads_owner_and_absence_and_leaves_nothing(helper_image, probe_image) -> None:
    before = _volumes()
    started = time.monotonic()
    data = probe_dir(probe_image, "/data")  # holds a 4 GB file: nothing is archived
    assert time.monotonic() - started < 30
    assert (data.uid, data.gid, data.mode, data.is_dir) == (1000, 1001, 0o750, True)
    assert probe_dir(probe_image, "/vol").uid == 70
    assert probe_dir(probe_image, "/absent") is None
    link = probe_dir(probe_image, "/link")
    assert link is not None and not link.is_dir  # the link itself, not /etc
    assert _volumes() - before == set()
