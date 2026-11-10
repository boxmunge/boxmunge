# SPDX-License-Identifier: Apache-2.0
"""One `docker ps` says which containers run each service of every Compose
project; check-all, health and the console ask it once per tick."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge import compose_inventory
from boxmunge.compose_inventory import FORMAT, parse
from boxmunge.docker_run import DockerError

# The real listing; the autouse fake_containers fixture replaces it per test.
REAL_INVENTORY = compose_inventory.running_inventory


def _rows(*rows: tuple[str, str, str, str]) -> str:
    return "".join("\t".join(r) + "\n" for r in rows)


def test_running_containers_by_project_and_service_names_sorted() -> None:
    inv = parse(_rows(("app-web-2", "app", "web", "False"), ("app-web-1", "app", "web", "False"),
                      ("custom", "app", "api", "False"), ("other-db-1", "other", "db", "")))
    assert inv.services("app") == {"api": ["custom"], "web": ["app-web-1", "app-web-2"]}
    assert inv.services("other") == {"db": ["other-db-1"]}
    assert inv.services("absent") == {}
    assert inv.is_running("app") and inv.is_running("app", "api")
    assert not inv.is_running("app", "worker") and not inv.is_running("absent")


def test_run_one_offs_are_not_service_containers() -> None:
    inv = parse(_rows(("app-web-run-1", "app", "web", "True"), ("app-web-1", "app", "web", "False")))
    assert inv.services("app") == {"web": ["app-web-1"]}


def test_a_container_without_a_service_label_blinds_only_its_project() -> None:
    inv = parse(_rows(("stray", "app", "", "False"), ("ok-web-1", "ok", "web", "False")))
    assert inv.services("ok") == {"web": ["ok-web-1"]}
    with pytest.raises(DockerError, match="stray carries the compose project label but no"):
        inv.services("app")


def test_an_unreadable_line_fails_loudly() -> None:
    with pytest.raises(DockerError, match="not 4 tab-separated fields"):
        parse("app-web-1 app web\n")


@pytest.mark.parametrize("project,scope", [
    (None, ["--filter", "label=com.docker.compose.project"]),
    ("app", ["--filter", "label=com.docker.compose.project=app"]),
])
def test_one_docker_ps_of_running_containers(monkeypatch, project, scope) -> None:
    seen = []

    def run(cmd, **kw):
        seen.append((cmd, kw["timeout"]))
        return subprocess.CompletedProcess(cmd, 0, "app-web-1\tapp\tweb\tFalse\n", "")

    monkeypatch.setattr(subprocess, "run", run)
    inv = REAL_INVENTORY(project, timeout=7)
    assert seen == [(["docker", "ps", *scope, "--format", FORMAT], 7)]
    assert "-a" not in seen[0][0]   # running containers only, as State.Running
    assert inv.services("app") == {"web": ["app-web-1"]}


def test_docker_failing_is_an_error_not_an_empty_box(monkeypatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 1, "", "Cannot connect to the Docker daemon"))
    with pytest.raises(DockerError, match="Cannot connect"):
        REAL_INVENTORY()
