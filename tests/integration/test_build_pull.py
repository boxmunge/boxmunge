# SPDX-License-Identifier: Apache-2.0
"""Pulling builds with real Docker and a local registry (#124).

Releases are built with --pull unless the operator passes --no-pull. A base
whose digest moved is built on; one that has not moved costs a registry
check and nothing else, also for a second compose project (a stage's build,
then a promote's). The pull never moves the base's tag in the local image
store, which is why promote pulls too. A registry that cannot be reached
fails the build and names --no-pull; a service whose compose.yml sets
`build: {pull: false}` builds from the local image store meanwhile.
"""
from __future__ import annotations

import random
import socket
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

from boxmunge.commands.deploy_images import build_and_pull
from boxmunge.docker_run import DockerError
from boxmunge.release_target import ReleaseTarget
from boxmunge.staged_release import ComposeTarget
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

_ALPINE = "alpine:3.20"      # also used by the other integration tests
_REGISTRY = "registry:2"


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.fixture(scope="module")
def registry():
    """A throwaway registry on a free local port; yields its host:port."""
    _docker("pull", "-q", _ALPINE)
    _docker("pull", "-q", _REGISTRY)
    name = f"bmpull-registry-{uuid.uuid4().hex[:8]}"
    # A port outside the ephemeral range: Docker Desktop's daemon cannot
    # reach a registry published on one of those through localhost.
    port = _free_port(random.Random().randrange(20000, 29000))
    _docker("run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:5000", _REGISTRY)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/v2/", timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail("the test registry did not come up")
        yield f"localhost:{port}"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _base(tmp_path: Path, ref: str, version: str) -> str:
    """Build a base image whose /base-version says `version`, tagged `ref`;
    returns its image ID."""
    d = tmp_path / f"base-{version}"
    d.mkdir()
    (d / "Dockerfile").write_text(f"FROM {_ALPINE}\nRUN echo {version} > /base-version\n")
    _docker("build", "-q", "-t", ref, str(d))
    return _docker("image", "inspect", "-f", "{{.Id}}", ref)


def _project(root: Path, bases: dict[str, str], pull_false: set[str] = frozenset()
             ) -> tuple[ReleaseTarget, dict[str, dict]]:
    """A compose project, one build service per entry of `bases`, each
    recording its base's version and a random token when its RUN step runs."""
    name = f"bmpull{uuid.uuid4().hex[:10]}"
    root.mkdir()
    lines = ["services:"]
    services = {}
    for svc, base in bases.items():
        (root / svc).mkdir()
        (root / svc / "Dockerfile").write_text(
            f"FROM {base}\nRUN cat /base-version > /seen "
            f"&& cat /proc/sys/kernel/random/uuid > /built\n")
        image = f"boxmunge.invalid/{name}/{svc}"
        pull = "      pull: false\n" if svc in pull_false else ""
        lines.append(f"  {svc}:\n    build:\n      context: ./{svc}\n{pull}    image: {image}")
        services[svc] = {"build": f"./{svc}", "image": image}
    (root / "compose.yml").write_text("\n".join(lines) + "\n")
    return ReleaseTarget(name, ComposeTarget(cwd=root, project_name=name,
                                             files=["compose.yml"])), services


def _read(image: str, path: str) -> str:
    return _docker("run", "--rm", image, "cat", path)


def _cleanup(*services: dict[str, dict]) -> None:
    images = [s["image"] for svcs in services for s in svcs.values()]
    subprocess.run(["docker", "image", "rm", "-f", *images], capture_output=True)


def test_a_moved_base_is_built_on_and_an_unchanged_one_stays_cached(registry, tmp_path) -> None:
    ref = f"{registry}/boxmunge-test/base:latest"
    v1 = _base(tmp_path, ref, "v1")
    _docker("push", "-q", ref)
    keep = f"boxmunge-test-keep/base:{uuid.uuid4().hex[:8]}"
    _docker("tag", v1, keep)  # the containerd store drops an image no name holds
    stage, stage_svcs = _project(tmp_path / "stage", {"web": ref})
    prod, prod_svcs = _project(tmp_path / "prod", {"web": ref})
    web = stage_svcs["web"]["image"]
    try:
        build_and_pull(stage, stage_svcs, pull=True)
        assert _read(web, "/seen") == "v1"
        # Another compose project over the same base and context: cached.
        build_and_pull(prod, prod_svcs, pull=True)
        assert _read(prod_svcs["web"]["image"], "/built") == _read(web, "/built")

        _base(tmp_path, ref, "v2")
        _docker("push", "-q", ref)
        _docker("tag", v1, ref)  # the box's tag still names v1, as on a real box
        build_and_pull(stage, stage_svcs, pull=True)
        assert _read(web, "/seen") == "v2"
        assert _docker("image", "inspect", "-f", "{{.Id}}", ref) == v1, \
            "the pull moved the local tag; promote would not need --pull"
        build_and_pull(prod, prod_svcs, pull=False)
        assert _read(prod_svcs["web"]["image"], "/seen") == "v1"
        build_and_pull(prod, prod_svcs, pull=True)
        assert _read(prod_svcs["web"]["image"], "/seen") == "v2"
    finally:
        _cleanup(stage_svcs, prod_svcs)
        subprocess.run(["docker", "image", "rm", "-f", ref, keep], capture_output=True)


def _free_port(start: int) -> int:
    """The first port from `start` nothing on this host listens on."""
    for port in range(start, start + 200):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise RuntimeError(f"no free port from {start}")


def _unused_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_an_unreachable_registry_fails_naming_no_pull(tmp_path) -> None:
    """The base is in the local image store under a registry name nothing
    serves: the pulling build fails, and only --no-pull builds from it."""
    _docker("pull", "-q", _ALPINE)
    base = f"127.0.0.1:{_unused_port()}/boxmunge-test/base:{uuid.uuid4().hex[:8]}"
    _base(tmp_path, base, "v1")
    target, services = _project(tmp_path / "app", {"web": base})
    try:
        with pytest.raises(DockerError) as e:
            build_and_pull(target, services, pull=True)
        assert "--no-pull" in str(e.value) and base in str(e.value)
        build_and_pull(target, services, pull=False)
        assert _read(services["web"]["image"], "/seen") == "v1"
    finally:
        _cleanup(services)
        subprocess.run(["docker", "image", "rm", "-f", base], capture_output=True)


def test_a_local_only_base_builds_with_pull_false_while_others_pull(registry, tmp_path) -> None:
    pulled = f"{registry}/boxmunge-test/shared:latest"
    _base(tmp_path, pulled, "registry")
    _docker("push", "-q", pulled)
    local = f"boxmunge-test-local/base:{uuid.uuid4().hex[:8]}"  # no registry serves it
    _base(tmp_path, local, "local")
    target, services = _project(tmp_path / "app", {"web": pulled, "tool": local},
                                pull_false={"tool"})
    try:
        build_and_pull(target, services, pull=True)
        assert _read(services["tool"]["image"], "/seen") == "local"
        assert _read(services["web"]["image"], "/seen") == "registry"
    finally:
        _cleanup(services)
        subprocess.run(["docker", "image", "rm", "-f", pulled, local], capture_output=True)
