# SPDX-License-Identifier: Apache-2.0
"""The helper under a remapped daemon: container-side owners, S+N on the host."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge import data_helper
from boxmunge.staging_placeholders import make_placeholder
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND


@pytest.fixture(scope="module")
def helper_image(remapped_daemon):
    # busybox stands in for the system image here: the helper needs only
    # sh, cp, chown, rm and ls, which both provide.
    subprocess.run(["docker", "tag", BUSYBOX, data_helper.HELPER_IMAGE], check=True)
    yield remapped_daemon
    subprocess.run(["docker", "image", "rm", data_helper.HELPER_IMAGE], check=True,
                   capture_output=True)


def _volume(name: str) -> None:
    subprocess.run(["docker", "volume", "create", name], check=True, capture_output=True)


def test_copy_keeps_container_owners_and_daemon_creates_the_destination(
        helper_image, tmp_path) -> None:
    s = helper_image
    _volume("hr_src")
    _volume("hr_fresh")
    try:
        data_helper.run_helper("t", data_helper.volume("hr_src", "/x"),
                               "echo s > /x/f && chown 999:999 /x/f && chmod 600 /x/f")
        dst = tmp_path / "dst-staging"
        data_helper.run_helper("t", [*data_helper.volume("hr_src", "/src", ro=True),
                                     *data_helper.bind(dst, "/dst")], "cp -a /src/. /dst/")
        assert (dst / "f").stat().st_uid == s + 999
        assert (dst / "f").stat().st_mode & 0o777 == 0o600
        data_helper.chown_at("t", data_helper.volume("hr_fresh", "/x"), "/x", 10001, 10001,
                             recursive=False)
        assert data_helper.volume_is_empty("t", "hr_fresh")
        assert not data_helper.volume_is_empty("t", "hr_src")
        data_helper.copy_into_volume("t", "hr_src", "hr_fresh")
        assert not data_helper.volume_is_empty("t", "hr_fresh")
        data_helper.empty_dir("t", dst)
        assert list(dst.iterdir()) == []
    finally:
        subprocess.run(["docker", "volume", "rm", "hr_src", "hr_fresh"], check=True,
                       capture_output=True)


def test_placeholders_belong_to_container_root(helper_image, tmp_path) -> None:
    s = helper_image
    project_dir = tmp_path / "myapp"
    project_dir.mkdir()
    make_placeholder("myapp", project_dir, "uploads-staging", is_file=False, remapped=True)
    make_placeholder("myapp", project_dir, "store-staging/deep/app.db", is_file=True,
                     remapped=True)
    assert (project_dir / "uploads-staging").stat().st_uid == s
    for rel in ("store-staging", "store-staging/deep", "store-staging/deep/app.db"):
        assert (project_dir / rel).stat().st_uid == s, rel
    assert (project_dir / "store-staging/deep/app.db").is_file()
