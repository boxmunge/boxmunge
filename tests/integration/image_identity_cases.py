# SPDX-License-Identifier: Apache-2.0
"""A deployed build service's image, across the starts after its deploy,
against a real daemon (plain here, and on both image stores in the dind job).

A start runs the image its deploy built; it never builds. Before 0.11.3 an
upgrade restart ran `compose up --build`. On the containerd image store
that moved the image's name to a new index (a fresh provenance
attestation, even from cache) while Compose, which compares the platform
manifest, left the container on the old index, which the store then
dropped: `docker image inspect` of the container's image failed, and with
it every listing of the project's containers (check's smoke, the CVE scan,
container-update, resume).
"""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

import pytest

from boxmunge.commands.upgrade_steps import restart_projects
from boxmunge.docker_containers import project_containers
from boxmunge.docker_run import DockerError
from boxmunge.paths import BoxPaths
from tests.integration import nonroot_cases as nc


def box_paths(root: Path) -> BoxPaths:
    """A boxmunge root of its own: restart_projects restarts every project in it."""
    for sub in ("config", "projects", "state/deploy", "state/health", "logs",
                "caddy/sites", "system", "upgrade-state"):
        (root / sub).mkdir(parents=True)
    (root / "config" / "boxmunge.yml").write_text(
        "hostname: images.localhost\nadmin_email: ops@example.com\n")
    return BoxPaths(root=root)


def project_name() -> str:
    return f"bmimg{uuid.uuid4().hex[:8]}"


def _bundle(project: str, marker: str) -> dict[str, str]:
    return nc.bundle(project, {"web": {"build": ".", "command": nc.SLEEP}},
                     files={"Dockerfile": f"FROM {nc.BUSYBOX}\nCOPY marker /marker\n",
                            "marker": marker})


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True,
                          timeout=300).stdout.strip()


def _web(project: str) -> dict:
    (doc,) = json.loads(_docker("container", "inspect", f"{project}-web-1"))
    return doc


def _image_present(image_id: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", image_id],
                          capture_output=True).returncode == 0


def containerd_store() -> bool:
    return "io.containerd.snapshotter" in _docker("info", "--format", "{{json .DriverStatus}}")


def _restart(paths: BoxPaths, project: str) -> None:
    result = restart_projects(paths, refused=())
    assert result.succeeded == [project], result


def case_restart_starts_the_deployed_image(paths: BoxPaths, project: str, capsys) -> None:
    """The build context changed on disk after the deploy: the restart still
    runs the deployed image, and its container's image stays inspectable."""
    rc, out = nc.deploy(paths, project, _bundle(project, "deployed\n"), capsys)
    assert rc == 0, out
    before = _web(project)
    (paths.project_dir(project) / "marker").write_text("edited after the deploy\n")
    _restart(paths, project)
    after = _web(project)
    assert after["Id"] == before["Id"] and after["Image"] == before["Image"]
    assert _image_present(after["Image"])
    assert nc.compose(paths, project, "exec", "-T", "web", "cat", "/marker") == "deployed\n"
    assert [c.name for c in project_containers(project)] == [f"{project}-web-1"]


def case_a_start_recreates_a_container_whose_image_is_gone(
        paths: BoxPaths, project: str, capsys) -> None:
    """A cached rebuild of the deployed name, by hand: on the containerd
    store it takes the running container's image away; the listing says so
    and the next start recreates the container from the deployed image. On
    the graph driver the image cannot go while a container uses it.

    Whether Compose's own up already recreates it differs between Compose
    versions (the dind job's 5.6 leaves it, as the affected box's 5.7 did,
    to the start's own recreate); the container must come back either way."""
    rc, out = nc.deploy(paths, project, _bundle(project, "deployed\n"), capsys)
    assert rc == 0, out
    before = _web(project)
    nc.compose(paths, project, "build", "web")
    if not containerd_store():
        assert _image_present(before["Image"])
        assert [c.image_id for c in project_containers(project)] == [before["Image"]]
        return
    assert not _image_present(before["Image"])
    with pytest.raises(DockerError) as gone:
        project_containers(project)
    assert f"{project}-web-1" in str(gone.value) and "no longer has" in str(gone.value)
    _restart(paths, project)
    after = _web(project)
    assert after["Id"] != before["Id"] and _image_present(after["Image"])
    assert nc.compose(paths, project, "exec", "-T", "web", "cat", "/marker") == "deployed\n"
    assert [c.image_id for c in project_containers(project)] == [after["Image"]]


def teardown(paths: BoxPaths, project: str) -> None:
    nc.teardown(paths, project)
