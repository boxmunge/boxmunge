# SPDX-License-Identifier: Apache-2.0
"""What each lifecycle operation asks of Docker (deep review E-1 to E-4, E-7).

A `docker compose config` costs 0.3 to 0.8 s on a VPS, and an upgrade pays
a production start for every project. These pin the counts per operation:
a change that resolves a model once more fails here, and the failure lists
every resolution with the functions that asked for it.

The unit tier builds no images (conftest stubs prepare_release_users, with
its pulls, builds and resolutions), so a deploy, stage or promote costs
more on a box than is counted here.
"""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.pause_cmd import run_pause
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.restore import run_restore
from boxmunge.commands.resume_cmd import run_resume
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.compose_guard import compose_up_checked
from boxmunge.project_registry import add_project
from tests.bundle_helpers import manifest_text, place_bundle
from tests.docker_call_counter import DockerCalls, docker_calls
from tests.fake_system_container import FakeSystemContainer
from tests.stage_helpers import V1, V2

SNAPSHOT = "myapp-2026-03-29T020000.tar.gz.age"


def _expect(seen: DockerCalls, *, compose_config: int, docker_info: int, other: int) -> None:
    expected = {"compose config": compose_config, "docker info": docker_info, "other": other}
    assert seen.counts() == expected, "\n".join([
        f"expected {expected}, counted {seen.counts()}",
        *(f"  compose config {c}" for c in seen.compose_config),
        *(f"  docker info: {c}" for c in seen.docker_info),
        *(f"  other: {c[:100]}" for c in seen.other),
    ])


@pytest.fixture
def box(paths):
    """A registered project with two bundles in the inbox."""
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    return paths


@pytest.fixture
def deployed(box):
    with docker_calls():
        assert run_deploy("myapp", box, ref=V1) == 0
    return box


def test_a_production_start(deployed) -> None:
    """What an upgrade's restart, a recover or a timer's start costs."""
    with docker_calls() as seen:
        compose_up_checked(deployed, "myapp", component="recover",
                           compose_files=["compose.yml", "compose.boxmunge.yml"])
    _expect(seen, compose_config=3, docker_info=1, other=4)


def test_a_bundle_deploy(deployed) -> None:
    with docker_calls() as seen:
        assert run_deploy("myapp", deployed, ref=V2) == 0
    _expect(seen, compose_config=8, docker_info=3, other=14)


def test_a_first_deploy_costs_what_a_redeploy_does(box) -> None:
    with docker_calls() as seen:
        assert run_deploy("myapp", box, ref=V1) == 0
    _expect(seen, compose_config=8, docker_info=3, other=14)


def test_stage_then_promote(deployed) -> None:
    with docker_calls() as seen:
        assert run_stage("myapp", deployed, ref=V2) == 0
    _expect(seen, compose_config=20, docker_info=6, other=5)
    with docker_calls() as seen:
        assert run_promote("myapp", deployed) == 0
    _expect(seen, compose_config=11, docker_info=3, other=17)


def test_resume(deployed) -> None:
    with docker_calls():
        assert run_pause("myapp", deployed, yes=True, no_snapshot=True) == 0
    with docker_calls() as seen:
        assert run_resume("myapp", deployed, yes=True, skip_security_checks=True) == 0
    _expect(seen, compose_config=6, docker_info=2, other=17)


def test_restore(box, monkeypatch) -> None:
    """Stop, start the backup service, restore into it, start everything."""
    place_bundle(box, timestamp=V1, files={
        "manifest.yml": manifest_text(backup="db-dump"),
        "dump.sh": "#!/bin/sh\n", "restore.sh": "#!/bin/sh\n"})
    with docker_calls():
        assert run_deploy("myapp", box, ref=V1) == 0
    box.project_backups("myapp").mkdir(exist_ok=True)
    (box.project_backups("myapp") / SNAPSHOT).write_bytes(b"encrypted")
    box.backup_key.parent.mkdir(parents=True, exist_ok=True)
    box.backup_key.write_text("# public key: age1test\nAGE-SECRET-KEY-1TEST\n")

    def age(cmd, **_kw):
        out = box.projects / cmd[cmd.index("-o") + 1].removeprefix("/projects/")
        out.write_bytes(b"a dump")
        return subprocess.CompletedProcess(cmd, 0)

    def answer(cmd, stdout=None, **_kw):
        if cmd[:2] == ["docker", "inspect"]:
            return "running healthy"
        if "exec" in cmd and hasattr(stdout, "write"):
            stdout.write(b"current data")   # the safety snapshot's dump
        return None

    FakeSystemContainer(box, handler=age).install(monkeypatch)
    with patch("boxmunge.commands.restore.time.sleep"), docker_calls(answer) as seen:
        assert run_restore("myapp", box, snapshot=SNAPSHOT, yes=True) == 0
    _expect(seen, compose_config=8, docker_info=3, other=13)
