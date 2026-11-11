"""An image run by digest across a save and load (docker load keeps no
digests): it is pulled again by that digest, and only once."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge.docker_run import docker_env
from boxmunge.userns import images as im
from boxmunge.userns.inventory import ImageEntry
from boxmunge.userns.journal import FORWARD, Journal
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND
S = 1048576


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], env=docker_env(), check=True, capture_output=True,
                          text=True).stdout


def test_an_image_run_by_digest_is_loaded_then_pulled_by_its_digest(tmp_path) -> None:
    _docker("pull", "-q", BUSYBOX)
    image_id = _docker("image", "inspect", "--format", "{{.Id}}", BUSYBOX).strip()
    img = ImageEntry(image_id, [], 1, True, refs=[BUSYBOX])
    j = Journal(FORWARD, "started", S)
    im.save_all([img], j, tmp_path / "b" / "img", lambda: None)
    _docker("image", "rm", "-f", image_id)
    im.load_all([img], j, tmp_path / "b" / "img", lambda: None)
    assert _docker("image", "inspect", "--format", "{{.Id}}", BUSYBOX).strip() == image_id
    assert j.items[f"image-ref:{BUSYBOX}"] == "pulled" and j.image_map[image_id] == image_id


def test_a_high_id_is_found_in_the_tar_the_migration_saves(tmp_path) -> None:
    """The forward save reads each tar it writes (by tag, as it saves; the
    containerd store's is an OCI layout of gzip blobs): the high-id image is
    refused and keeps no tar, busybox is saved."""
    _docker("pull", "-q", BUSYBOX)
    tag = "boxmunge.invalid/dind/highids-saved:1"
    subprocess.run(["docker", "build", "-q", "-t", tag, "-"], env=docker_env(), check=True,
                   capture_output=True, text=True,
                   input=f"FROM {BUSYBOX}\nRUN touch /big && chown 70000:70000 /big\n")
    try:
        clean = ImageEntry(_docker("image", "inspect", "--format", "{{.Id}}", BUSYBOX).strip(),
                           [], 1, True, refs=[BUSYBOX])
        high = ImageEntry(_docker("image", "inspect", "--format", "{{.Id}}", tag).strip(),
                          [tag], 1, True)
        j = Journal(FORWARD, "started", S)
        directory = tmp_path / "b" / "img"
        with pytest.raises(im.ImageError, match=r"ids above 65535 \(big \(70000:70000\)\)"):
            im.save_all([high, clean], j, directory, lambda: None, refuse_high_ids=True)
        assert j.items == {f"image:{clean.id}": "saved"}
        assert [f.name for f in directory.iterdir()] == [im.tar_path(directory, clean.id).name]
    finally:
        _docker("image", "rm", tag)
