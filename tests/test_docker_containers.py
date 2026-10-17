# SPDX-License-Identifier: Apache-2.0
"""Container discovery by Compose labels (docker_containers)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from boxmunge import docker_containers
from boxmunge.docker_run import DockerError

# Bound at import: conftest's fake_containers replaces the module attributes.
project_containers = docker_containers.project_containers
local_image = docker_containers.local_image
created_times = docker_containers.created_times

_IMG = "sha256:" + "a" * 64


def _container(name, service, *, image=_IMG, running=True, health=None, oneoff=False,
               restart="unless-stopped"):
    labels = {"com.docker.compose.project": "demo", "com.docker.compose.service": service}
    if oneoff:
        labels["com.docker.compose.oneoff"] = "True"
    state = {"Running": running, "ExitCode": 0}
    if health:
        state["Health"] = {"Status": health}
    return {"Name": f"/{name}", "Image": image, "Config": {"Labels": labels}, "State": state,
            "HostConfig": {"RestartPolicy": {"Name": restart}}}


@pytest.fixture
def daemon(monkeypatch):
    """Answers docker ps / container inspect / image inspect from a dict."""
    state = {"containers": [], "images": {_IMG: ["busybox@sha256:" + "b" * 64]}, "calls": []}

    def run(cmd, capture=False, **kwargs):
        state["calls"].append(cmd)
        out = MagicMock()
        if cmd[:2] == ["docker", "ps"]:
            out.stdout = "\n".join(c["Name"].lstrip("/") for c in state["containers"])
        elif cmd[:3] == ["docker", "container", "inspect"]:
            out.stdout = json.dumps(state["containers"])
        else:
            out.stdout = json.dumps([{"Id": i, "RepoDigests": d}
                                     for i, d in state["images"].items() if i in cmd])
        return out

    monkeypatch.setattr(docker_containers, "_run", run)
    return state


def test_containers_are_listed_by_project_label_whatever_their_names(daemon):
    daemon["containers"] = [_container("my-custom-web", "web", health="healthy"),
                            _container("demo-worker-2", "worker", running=False)]
    found = project_containers("demo")
    assert daemon["calls"][0][:3] == ["docker", "ps", "-a"]
    assert "label=com.docker.compose.project=demo" in daemon["calls"][0]
    assert [(c.name, c.service, c.running, c.health) for c in found] == [
        ("demo-worker-2", "worker", False, None), ("my-custom-web", "web", True, "healthy")]


def test_image_identity_and_display_reference_are_kept_apart(daemon):
    daemon["containers"] = [_container("demo-web-1", "web")]
    (web,) = project_containers("demo")
    assert web.image_id == _IMG
    assert web.image_ref == "busybox@sha256:" + "b" * 64


def test_a_locally_built_image_is_named_by_its_id(daemon):
    daemon["images"] = {_IMG: []}
    daemon["containers"] = [_container("demo-web-1", "web")]
    (web,) = project_containers("demo")
    assert web.image_ref == _IMG


def test_a_one_shot_that_exited_zero_finished_cleanly(daemon):
    daemon["containers"] = [_container("demo-migrate-1", "migrate", running=False, restart="no"),
                            _container("demo-web-1", "web", running=False)]
    migrate, web = project_containers("demo")
    assert (migrate.exit_code, migrate.finished_cleanly) == (0, True)
    # Exited 0 but its policy would restart it: not a finished one-shot.
    assert not web.finished_cleanly


def test_one_off_containers_are_marked(daemon):
    daemon["containers"] = [_container("demo-web-run-1", "web", oneoff=True)]
    (run,) = project_containers("demo")
    assert run.oneoff


def test_no_containers_is_an_empty_list(daemon):
    assert project_containers("demo") == []


def test_a_container_without_a_service_label_fails_loudly(daemon):
    stray = _container("stray", "web")
    del stray["Config"]["Labels"]["com.docker.compose.service"]
    daemon["containers"] = [stray]
    with pytest.raises(DockerError, match="stray"):
        project_containers("demo")


def test_docker_failure_is_not_an_empty_answer(monkeypatch):
    def run(cmd, capture=False, **kwargs):
        raise DockerError("Cannot connect to the Docker daemon")
    monkeypatch.setattr(docker_containers, "_run", run)
    with pytest.raises(DockerError):
        project_containers("demo")


def test_created_times_read_docker_nanosecond_times(daemon):
    web, worker = _container("demo-web-1", "web"), _container("demo-worker-1", "worker")
    web["Created"] = "2026-10-01T12:00:00.123456789Z"
    worker["Created"] = "2026-10-01T14:00:00+02:00"
    daemon["containers"] = [web, worker]
    assert created_times("demo") == {
        "demo-web-1": datetime(2026, 10, 1, 12, 0, 0, 123456, tzinfo=timezone.utc),
        "demo-worker-1": datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)}
    assert "label=com.docker.compose.project=demo" in daemon["calls"][0]


def test_created_times_of_no_containers_is_empty(daemon):
    assert created_times("demo") == {}


def test_an_unreadable_created_time_fails_loudly(daemon):
    web = _container("demo-web-1", "web")
    web["Created"] = "yesterday"
    daemon["containers"] = [web]
    with pytest.raises(DockerError, match="yesterday"):
        created_times("demo")


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    result = MagicMock()
    result.returncode, result.stdout, result.stderr = returncode, stdout, stderr
    return result


def test_local_image_names_the_image_a_ref_points_at(monkeypatch):
    out = json.dumps([{"Id": _IMG, "RepoDigests": ["nginx@sha256:" + "c" * 64]}])
    monkeypatch.setattr(docker_containers, "_run", lambda cmd, **k: _completed(0, out))
    image = local_image("nginx:1")
    assert image.image_id == _IMG and image.image_ref == "nginx@sha256:" + "c" * 64


def test_absent_local_image_is_none(monkeypatch):
    monkeypatch.setattr(docker_containers, "_run", lambda cmd, **k: _completed(
        1, stderr="Error response from daemon: No such image: x:1"))
    assert local_image("x:1") is None


def test_other_local_image_failures_raise(monkeypatch):
    monkeypatch.setattr(docker_containers, "_run", lambda cmd, **k: _completed(
        1, stderr="Cannot connect to the Docker daemon"))
    with pytest.raises(DockerError, match="Cannot connect"):
        local_image("x:1")
