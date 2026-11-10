# SPDX-License-Identifier: Apache-2.0
"""check-all runs every five minutes: one `docker ps` per tick says which
containers run every project's services, then one `docker exec` per smoke
(deep review E-2: it was three Docker calls per project). health's
project-containers check asks the same single listing."""
from __future__ import annotations

import subprocess

import pytest
import yaml

from boxmunge import compose_inventory
from boxmunge.commands.check import run_check_all, run_smoke_in_container
from boxmunge.health_checks.projects import check_project_containers
from boxmunge.paths import BoxPaths

# The real listing; the autouse fake_containers fixture replaces it per test.
REAL_INVENTORY = compose_inventory.running_inventory
PROJECTS = [f"p{i:02d}" for i in range(10)]
SMOKE = {"port": 8080, "routes": [{"path": "/"}], "smoke": "boxmunge-scripts/smoke.sh"}


class Docker:
    """Counts docker CLI calls; every project runs one `web` container."""

    def __init__(self, running: list[str]) -> None:
        self.running = running
        self.calls: list[list[str]] = []
        self.ps_fails = False

    def __call__(self, cmd, *a, **k):
        if cmd[0] != "docker":
            return subprocess.CompletedProcess(cmd, 0, "", "")
        self.calls.append(cmd)
        if cmd[1] == "ps":
            if self.ps_fails:
                return subprocess.CompletedProcess(cmd, 1, "", "daemon busy")
            scope = cmd[cmd.index("--filter") + 1].split("=")
            names = self.running if len(scope) == 2 else [p for p in self.running
                                                          if p == scope[2]]
            return subprocess.CompletedProcess(
                cmd, 0, "".join(f"{p}-web-1\t{p}\tweb\tFalse\n" for p in names), "")
        assert cmd[1] == "exec", cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def count(self, verb: str) -> int:
        return sum(1 for c in self.calls if c[1] == verb)


@pytest.fixture
def box(paths: BoxPaths, monkeypatch) -> Docker:
    paths.config_file.write_text("hostname: box.example.com\nadmin_email: ops@example.com\n")
    for name in PROJECTS:
        paths.project_dir(name).mkdir(parents=True)
        paths.project_manifest(name).write_text(yaml.dump({
            "schema_version": 3, "id": "01TEST", "project": name, "source": "bundle",
            "hosts": [f"{name}.example.com"], "services": {"web": SMOKE}}))
    docker = Docker(list(PROJECTS))
    monkeypatch.setattr(compose_inventory, "running_inventory", REAL_INVENTORY)
    monkeypatch.setattr(subprocess, "run", docker)
    return docker


@pytest.mark.parametrize("read_only", [True, False])
def test_a_check_all_tick_lists_containers_once(paths, box, read_only) -> None:
    assert run_check_all(paths, read_only=read_only) == 0
    assert box.count("ps") == 1
    assert box.count("exec") == len(PROJECTS)
    assert len(box.calls) == 1 + len(PROJECTS)


def test_health_project_containers_lists_containers_once(paths, box) -> None:
    check = check_project_containers(paths)
    assert check.status == "ok" and "All 10 project(s)" in check.detail
    assert len(box.calls) == 1


def test_a_service_missing_from_the_tick_listing_is_asked_again(paths, box) -> None:
    """A deploy that ended after the tick's listing recreated the service."""
    tick = compose_inventory.running_inventory()
    box.calls.clear()
    manifest = {"project": "late", "services": {"web": SMOKE}}
    box.running.append("late")
    result = run_smoke_in_container(paths.project_dir("late"), manifest, [], tick=lambda: tick)
    assert result.status == "ok"
    assert [c[1] for c in box.calls] == ["ps", "exec"]
    assert box.calls[0][3] == "label=com.docker.compose.project=late"


def test_a_failed_listing_is_reported_by_each_project_not_cached(paths, box, capsys) -> None:
    box.ps_fails = True
    assert run_check_all(paths, read_only=True) == 1
    out = capsys.readouterr().out
    assert out.count("smoke could not run (infrastructure, not app): cannot list the "
                      "containers of") == len(PROJECTS)
    assert box.count("ps") == len(PROJECTS) and box.count("exec") == 0
