# SPDX-License-Identifier: Apache-2.0
"""Smoke tests run in the containers Compose labels as the service's, so a
custom container_name and every running replica are tested, and a smoke
that overruns is killed in each of them. The containers are hardened the
way boxmunge runs a service: an init as PID 1, read-only root, no
capabilities, not root. One service, `bare`, turns the init off, as a
project's compose file may."""
from __future__ import annotations

import time
import uuid
from unittest.mock import patch

import pytest

from boxmunge.commands import check
from boxmunge.commands.check import run_smoke_in_container
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import BUSYBOX, compose, docker, ensure_busybox, tear_down

pytestmark = [pytest.mark.integration, skip_no_docker]


@pytest.fixture
def project(tmp_path):
    ensure_busybox()
    name = f"bmsmoke-{uuid.uuid4().hex[:8]}"
    (tmp_path / "scripts").mkdir()
    # /tmp/hang: a script that forks a child, both outliving the timeout.
    (tmp_path / "scripts" / "smoke.sh").write_text(
        "test ! -e /tmp/broken || { echo \"$(hostname) broken\" >&2; exit 1; }\n"
        "test ! -e /tmp/hang || { sleep 3001 & sleep 3002; }\n")
    common = ("    command: [sleep, '3600']\n    network_mode: none\n"
              "    read_only: true\n    cap_drop: [ALL]\n    user: '65534:65534'\n"
              "    pids_limit: 32\n    tmpfs: ['/tmp']\n"
              "    volumes: ['./scripts:/boxmunge-scripts:ro']\n")
    init, no_init = "    init: true\n", "    init: false\n"
    (tmp_path / "compose.yml").write_text(
        "services:\n"
        f"  web:\n    image: {BUSYBOX}\n    container_name: {name}-custom\n{common}{init}"
        f"  worker:\n    image: {BUSYBOX}\n    deploy:\n      replicas: 2\n{common}{init}"
        f"  bare:\n    image: {BUSYBOX}\n{common}{no_init}")
    compose(tmp_path, name, "up", "-d")
    manifest = {"project": name, "services": {
        s: {"port": 80, "routes": [], "smoke": "boxmunge-scripts/smoke.sh"}
        for s in ("web", "worker", "bare")}}
    yield tmp_path, name, manifest
    tear_down(tmp_path, name, [])


def test_custom_name_and_replicas_pass(project):
    project_dir, _, manifest = project
    assert run_smoke_in_container(project_dir, manifest, ["compose.yml"]).status == "ok"


def test_a_failing_second_replica_is_caught(project):
    project_dir, name, manifest = project
    docker("exec", f"{name}-worker-2", "touch", "/tmp/broken")
    result = run_smoke_in_container(project_dir, manifest, ["compose.yml"])
    assert result.status == "warning"
    assert "broken" in result.message


def _processes(container: str) -> list[str]:
    """Every process entry in the container (this listing's shell included),
    by command name; one killed and not yet reaped is marked a zombie."""
    listing = ('for f in /proc/[0-9]*/stat; do read -r line < "$f" || continue; '
               'set -- $line; [ "$3" = Z ] && echo "$2 zombie" || echo "$2"; done')
    return sorted(docker("exec", container, "sh", "-c", listing).splitlines())


def test_a_smoke_that_overruns_is_killed_in_every_replica(project):
    """0.11.6 audit F04: the timeout killed the docker client and left the
    script and its child running in the container, more of them every tick."""
    project_dir, name, manifest = project
    workers = [f"{name}-worker-1", f"{name}-worker-2"]
    before = {c: _processes(c) for c in workers}
    for container in workers:
        docker("exec", container, "touch", "/tmp/hang")
    with patch.object(check, "SMOKE_TIMEOUT", 3):
        result = run_smoke_in_container(project_dir, manifest, ["compose.yml"])
    assert result.status == "warning"
    assert (f"Smoke test for worker timed out (3s) in container {workers[0]} "
            "and was stopped there") in result.message
    # Nothing of either replica's smoke is left, once init has reaped the killed.
    deadline = time.monotonic() + 10
    while {c: _processes(c) for c in workers} != before and time.monotonic() < deadline:
        time.sleep(0.5)
    assert {c: _processes(c) for c in workers} == before
    # The next tick starts from nothing left behind and judges the app itself.
    for container in workers:
        docker("exec", container, "rm", "/tmp/hang")
    assert run_smoke_in_container(project_dir, manifest, ["compose.yml"]).status == "ok"


def test_without_an_init_the_killed_smoke_is_said_to_leave_its_entries(project):
    """PID 1 of a container run with `init: false` is the app, which reaps
    nothing it did not start: the killed smoke runs no more, and its entries
    stay listed (and counted against the pids limit) until a restart."""
    project_dir, name, manifest = project
    container = f"{name}-bare-1"
    before = _processes(container)
    docker("exec", container, "touch", "/tmp/hang")
    with patch.object(check, "SMOKE_TIMEOUT", 3):
        result = run_smoke_in_container(project_dir, manifest, ["compose.yml"])
    assert result.status == "warning"
    assert result.message == (
        f"Smoke test for bare timed out (3s) in container {container} and was killed "
        "there; its finished process entries remain until the container restarts, "
        "because the container runs without an init process")
    after = _processes(container)
    assert [p for p in after if not p.endswith(" zombie")] == before  # nothing is running
    assert [p for p in after if p.endswith(" zombie")], "the limit this message reports"
    # The next tick is not held up by what was left, and judges the app itself.
    docker("exec", container, "rm", "/tmp/hang")
    assert run_smoke_in_container(project_dir, manifest, ["compose.yml"]).status == "ok"
