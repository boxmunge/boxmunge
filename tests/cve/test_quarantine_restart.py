# SPDX-License-Identifier: Apache-2.0
"""Quarantine holds across a Docker daemon restart (audit B-19)."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge import docker
from boxmunge.cve import quarantine as q
from boxmunge.docker import DockerError
from tests.test_commands.cve_helpers import Docker, make_box, seed_quarantine


@pytest.fixture
def box(tmp_path, monkeypatch):
    paths = make_box(tmp_path, services=("web", "worker"))
    fake = Docker(monkeypatch)
    fake.policies = {"demo-web-1": "unless-stopped", "demo-worker-1": "always",
                     "demo-cron-1": "no", "other-web-1": "always"}
    return paths, fake


def _reassert(paths):
    q.reassert_quarantine(
        "demo", paths, project_dir=paths.project_dir("demo"),
        hosts=["demo.example.com"], compose_files=["compose.yml"],
    )


def test_quarantine_disables_restart_and_saves_originals(box):
    paths, fake = box
    seed_quarantine(paths, action_complete=False)
    _reassert(paths)
    assert fake.policies == {"demo-web-1": "no", "demo-worker-1": "no",
                             "demo-cron-1": "no", "other-web-1": "always"}
    record = q.read_quarantine_state("demo", paths)
    assert record["restart_policies"] == {
        "demo-web-1": "unless-stopped", "demo-worker-1": "always", "demo-cron-1": "no",
    }
    assert record["action_complete"] is True


def test_reassert_keeps_the_original_policies(box):
    """The second pass sees "no" everywhere and must not record it."""
    paths, fake = box
    seed_quarantine(paths, action_complete=False)
    _reassert(paths)
    _reassert(paths)
    record = q.read_quarantine_state("demo", paths)
    assert record["restart_policies"]["demo-worker-1"] == "always"


def test_reassert_repins_a_policy_reset_behind_its_back(box):
    paths, fake = box
    seed_quarantine(paths)
    _reassert(paths)
    fake.policies["demo-worker-1"] = "always"  # someone ran docker update
    _reassert(paths)
    assert fake.policies["demo-worker-1"] == "no"


def test_lift_restores_policies_before_starting(box):
    paths, fake = box
    seed_quarantine(paths)
    _reassert(paths)
    fake.calls.clear()
    q.lift_quarantine(
        "demo", paths, project_dir=paths.project_dir("demo"),
        project_caddy_site_content="demo.example.com {}\n",
        compose_files=["compose.yml"],
    )
    assert fake.policies == {"demo-web-1": "unless-stopped", "demo-worker-1": "always",
                             "demo-cron-1": "no", "other-web-1": "always"}
    assert fake.calls == ["caddy_reload", "compose_up"]
    assert not q.is_quarantined("demo", paths)


def test_pinning_failure_leaves_the_action_incomplete(box, monkeypatch):
    paths, fake = box
    seed_quarantine(paths, action_complete=False)

    def boom(names, policy):
        raise DockerError("daemon not responding")

    monkeypatch.setattr("boxmunge.restart_hold.set_restart_policy", boom)
    with pytest.raises(q.QuarantineError, match="restart policies"):
        _reassert(paths)
    assert not q.quarantine_action_complete("demo", paths)


# ---------- docker primitives (output parsing; Docker itself stubbed) ----------


def _completed(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_project_restart_policies_parses_inspect(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1] == "ps":
            return _completed("demo-web-1\ndemo-worker-1\n")
        return _completed("/demo-web-1|always|0\n/demo-worker-1|on-failure|3\n")

    monkeypatch.setattr(docker, "_run", fake_run)
    assert docker.project_restart_policies("demo") == {
        "demo-web-1": "always", "demo-worker-1": "on-failure:3",
    }
    assert "label=com.docker.compose.project=demo" in calls[0]


def test_project_restart_policies_empty_project(monkeypatch):
    monkeypatch.setattr(docker, "_run", lambda cmd, **kw: _completed(""))
    assert docker.project_restart_policies("demo") == {}


def test_project_restart_policies_rejects_garbage(monkeypatch):
    def fake_run(cmd, **kwargs):
        return _completed("demo-web-1\n" if cmd[1] == "ps" else "nonsense\n")

    monkeypatch.setattr(docker, "_run", fake_run)
    with pytest.raises(DockerError, match="unexpected docker inspect output"):
        docker.project_restart_policies("demo")


def test_set_restart_policy_runs_docker_update(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(docker, "_run", lambda cmd, **kw: calls.append(cmd))
    docker.set_restart_policy(["a-1", "b-1"], "no")
    docker.set_restart_policy([], "no")
    assert calls == [["docker", "update", "--restart=no", "a-1", "b-1"]]
