"""The image probe on a real (unremapped) daemon leaves nothing behind."""
from __future__ import annotations

import subprocess
import uuid

import pytest

from boxmunge.image_probe import probe_dir
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import build_image

pytestmark = [pytest.mark.integration, skip_no_docker]

DOCKERFILE = ("RUN mkdir /data /vol && chown 1000:1001 /data && chmod 750 /data && "
              "chown 70:70 /vol\nVOLUME /vol\n")


@pytest.fixture(scope="module")
def probe_image():
    tag = f"boxmunge-probe-test:{uuid.uuid4().hex[:8]}"
    yield build_image(tag, "probe", DOCKERFILE)
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)


def _volumes() -> set[str]:
    return set(subprocess.run(["docker", "volume", "ls", "-q"], check=True,
                              capture_output=True, text=True).stdout.split())


def _probes() -> list[str]:
    return subprocess.run(["docker", "ps", "-aq", "--filter", "name=boxmunge-probe-"],
                          check=True, capture_output=True, text=True).stdout.split()


def test_probe_reads_owner_and_absence_and_leaves_nothing(probe_image) -> None:
    before = _volumes()
    data = probe_dir(probe_image, "/data", 0)
    assert (data.uid, data.gid, data.mode, data.is_dir) == (1000, 1001, 0o750, True)
    assert probe_dir(probe_image, "/vol", 0).uid == 70
    assert probe_dir(probe_image, "/absent", 0) is None
    assert _volumes() - before == set()
    assert _probes() == []
