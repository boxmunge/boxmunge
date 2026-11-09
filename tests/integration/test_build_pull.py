# SPDX-License-Identifier: Apache-2.0
"""A pulling build with real Docker (#124).

Releases are built with --pull unless the operator passes --no-pull. Over
a base image whose digest has not moved, that must cost a registry check
and nothing else: every step after FROM stays cached. A registry that
cannot be reached fails the build and names --no-pull; --no-pull builds
from the local base.
"""
from __future__ import annotations

import socket
import subprocess
import uuid
from pathlib import Path

import pytest

from boxmunge.commands.deploy_images import build_and_pull
from boxmunge.docker_run import DockerError
from boxmunge.release_target import ReleaseTarget
from boxmunge.staged_release import ComposeTarget
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

_BASE = "alpine:3.20"


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _project(tmp_path: Path, base: str) -> tuple[ReleaseTarget, str]:
    """A one-service build whose RUN step records when it ran."""
    name = f"bmpull{uuid.uuid4().hex[:10]}"
    image = f"boxmunge.invalid/{name}/web"
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Dockerfile").write_text(
        f"FROM {base}\nRUN cat /proc/sys/kernel/random/uuid > /built\n")
    (tmp_path / "compose.yml").write_text(
        f"services:\n  web:\n    build: ./app\n    image: {image}\n")
    return ReleaseTarget(name, ComposeTarget(cwd=tmp_path, project_name=name,
                                             files=["compose.yml"])), image


def _built(image: str) -> str:
    return _docker("run", "--rm", image, "cat", "/built")


def _services(image: str) -> dict[str, dict]:
    return {"web": {"build": "./app", "image": image}}


def _unused_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_a_pulling_rebuild_over_an_unchanged_base_is_fully_cached(tmp_path) -> None:
    _docker("pull", "-q", _BASE)
    target, image = _project(tmp_path, _BASE)
    try:
        build_and_pull(target, _services(image), pull=True)
        first = _built(image)
        build_and_pull(target, _services(image), pull=True)
        assert _built(image) == first, "the RUN step ran again over an unchanged base"
    finally:
        subprocess.run(["docker", "image", "rm", "-f", image], capture_output=True)


def test_an_unreachable_registry_fails_naming_no_pull(tmp_path) -> None:
    """The base is on the box under a registry name nothing serves: the
    pulling build fails, and only --no-pull builds from it."""
    _docker("pull", "-q", _BASE)
    base = f"127.0.0.1:{_unused_port()}/boxmunge-test/base:{uuid.uuid4().hex[:8]}"
    _docker("tag", _BASE, base)
    target, image = _project(tmp_path, base)
    try:
        with pytest.raises(DockerError) as e:
            build_and_pull(target, _services(image), pull=True)
        assert "--no-pull" in str(e.value) and base in str(e.value)
        build_and_pull(target, _services(image), pull=False)
        assert _built(image)
    finally:
        subprocess.run(["docker", "image", "rm", "-f", image, base], capture_output=True)
