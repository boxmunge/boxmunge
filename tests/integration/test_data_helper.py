# SPDX-License-Identifier: Apache-2.0
"""The helper on a real (unremapped) daemon, from the real system image.

Owners are read inside a container: Docker Desktop shows bind-mounted files
as the host user on the host side (CI on Linux is the authoritative run).
"""
from __future__ import annotations

import subprocess

import pytest

from boxmunge import data_helper
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]


def _as_root(path, script: str) -> None:
    subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{path}:/x",
                    "busybox:1.36", "sh", "-c", script], check=True, capture_output=True)


def test_copies_and_empties_container_owned_data(helper_image, tmp_path) -> None:
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    _as_root(src, "echo s > /x/f && chown 999:999 /x/f && chmod 600 /x/f && "
                  "mkdir /x/d && chown 70:70 /x/d && chmod 700 /x/d && touch /x/.hidden")
    data_helper.run_helper("it", [*data_helper.bind(src, "/src", ro=True),
                                  *data_helper.bind(dst, "/dst")], "cp -a /src/. /dst/")
    assert data_helper.run_helper(
        "it", data_helper.bind(dst, "/x", ro=True),
        '[ "$(stat -c %u:%a /x/f)" = 999:600 ] && [ "$(stat -c %u:%a /x/d)" = 70:700 ] '
        '&& [ -e /x/.hidden ]', check=False) == 0
    data_helper.empty_dir("it", dst)
    assert list(dst.iterdir()) == []
    data_helper.empty_dir("it", src)


def test_volume_operations(helper_image) -> None:
    import uuid
    src, dst = f"bmdh{uuid.uuid4().hex[:8]}_src", f"bmdh{uuid.uuid4().hex[:8]}_dst"
    try:
        for name in (src, dst):
            subprocess.run(["docker", "volume", "create", name], check=True, capture_output=True)
        assert data_helper.volume_is_empty("it", src)
        data_helper.run_helper("it", data_helper.volume(src, "/x"),
                               "echo s > /x/f && chown 999:999 /x/f && chmod 600 /x/f")
        assert not data_helper.volume_is_empty("it", src)
        data_helper.chown_at("it", data_helper.volume(dst, "/x"), "/x", 10001, 10001,
                             recursive=False)
        data_helper.copy_into_volume("it", src, dst)
        rc = data_helper.run_helper(
            "it", data_helper.volume(dst, "/x", ro=True),
            '[ "$(stat -c %u:%a /x/f)" = 999:600 ] && [ "$(cat /x/f)" = s ]', check=False)
        assert rc == 0
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", src, dst], capture_output=True)


def test_the_helper_cannot_write_its_rootfs(helper_image) -> None:
    assert data_helper.run_helper("it", [], "touch /etc/x", check=False) != 0
