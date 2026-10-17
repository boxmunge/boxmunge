# SPDX-License-Identifier: Apache-2.0
"""The helper on a real (unremapped) daemon, from the real system image.

Owners are read inside a container: Docker Desktop shows bind-mounted files
as the host user on the host side (CI on Linux is the authoritative run).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from boxmunge import data_helper
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import BUSYBOX, ensure_busybox

pytestmark = [pytest.mark.integration, skip_no_docker]


def _as_root(path, script: str) -> None:
    ensure_busybox()
    subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{path}:/x",
                    BUSYBOX, "sh", "-c", script], check=True, capture_output=True)


def test_copies_and_empties_container_owned_data(helper_image, tmp_path) -> None:
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    _as_root(src, "echo s > /x/f && chown 999:999 /x/f && chmod 600 /x/f && "
                  "mkdir /x/d && chown 70:70 /x/d && chmod 700 /x/d && touch /x/.hidden")
    data_helper.run_helper("it", ["-v", f"{src}:/src:ro", "-v", f"{dst}:/dst"],
                           "cp -a /src/. /dst/")
    assert data_helper.run_helper(
        "it", ["-v", f"{dst}:/x:ro"],
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
        data_helper.copy_into_volume("it", src, dst)
        rc = data_helper.run_helper(
            "it", data_helper.volume(dst, "/x", ro=True),
            '[ "$(stat -c %u:%a /x/f)" = 999:600 ] && [ "$(cat /x/f)" = s ]', check=False)
        assert rc == 0
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", src, dst], capture_output=True)


def test_the_helper_cannot_write_its_rootfs(helper_image) -> None:
    assert data_helper.run_helper("it", [], "touch /etc/x", check=False) != 0


def test_a_link_in_container_data_cannot_redirect_the_emptying(helper_image, tmp_path) -> None:
    """A container swaps its data directory for a link out of the project:
    the helper reaches it inside its own namespace and refuses it, and
    nothing outside the project is touched."""
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep").write_text("not the project's")
    project = tmp_path / "projects" / "myapp"
    (project / "data").mkdir(parents=True)
    for target in ("../../../victim", str(victim)):
        (project / "data" / "pg").unlink(missing_ok=True)
        (project / "data" / "pg").symlink_to(target)
        with pytest.raises(data_helper.DockerError, match="through a symlink"):
            data_helper.empty_under("it", project, Path("data/pg"))
        assert (victim / "keep").read_text() == "not the project's"


def test_empty_under_empties_container_owned_data(helper_image, tmp_path) -> None:
    project = tmp_path / "myapp"
    (project / "data" / "pg").mkdir(parents=True)
    _as_root(project / "data" / "pg", "mkdir -p /x/base && echo x > /x/base/f && "
             "touch /x/.hidden && chown -R 999:999 /x/base && chmod -R go-rwx /x/base")
    data_helper.empty_under("it", project, Path("data/pg"))
    assert list((project / "data" / "pg").iterdir()) == []



def _project_with_link(tmp_path) -> tuple[Path, Path]:
    """A project whose data/ a container swapped for a link to a sibling."""
    sibling = tmp_path / "sibling"
    (sibling / "uploads").mkdir(parents=True)
    project = tmp_path / "projects" / "myapp"
    project.mkdir(parents=True)
    (project / "data").symlink_to(sibling)
    return project, sibling


def test_mkdir_under_refuses_a_planted_link_on_the_way(helper_image, tmp_path) -> None:
    project, sibling = _project_with_link(tmp_path)
    with pytest.raises(data_helper.DockerError, match="through a symlink"):
        data_helper.mkdir_under("it", project, Path("data/new"), (10001, 10001))
    assert not (sibling / "new").exists()


def test_chown_under_refuses_a_planted_link_and_gives_the_rest(helper_image, tmp_path) -> None:
    project, sibling = _project_with_link(tmp_path)
    with pytest.raises(data_helper.DockerError, match="through a symlink"):
        data_helper.chown_under("it", project, Path("data/uploads"), (10001, 10001))
    real = project / "uploads"
    real.mkdir()
    (real / "f").write_text("x")
    data_helper.mkdir_under("it", project, Path("made"), (10001, 10001))
    data_helper.chown_under("it", project, Path("uploads"), (10001, 10001))
    assert data_helper.run_helper(
        "it", ["-v", f"{project}:/x:ro"],
        '[ "$(stat -c %u /x/uploads/f)" = 10001 ] && [ "$(stat -c %u /x/made)" = 10001 ]',
        check=False) == 0
    data_helper.empty_dir("it", real)
