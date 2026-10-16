"""Integration: a container cannot hand root a compose file or mount nobody checked.

Root-run paths (upgrade, container-update, recover, ...) re-run `docker
compose up` on the files in the project directory long after deploy
validated them. These tests use real `docker compose config` and a real
filesystem. No container is started: `up` and `start` are intercepted at
the subprocess runner, so the tests see exactly which compose commands
would have run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from boxmunge import docker
from boxmunge.paths import BoxPaths

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]

PROJECT = "guardint"


def _paths(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.config, paths.projects, paths.deploy_state, paths.logs, paths.caddy_sites):
        d.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(
        "hostname: guard.example.com\nadmin_email: ops@example.com\n"
        "pushover:\n  user_key: u\n  app_token: t\n")
    return paths


def _manifest() -> dict:
    return {
        "schema_version": 2, "id": "01JGUARDINT0000000000000000", "project": PROJECT,
        "source": "bundle", "hosts": [f"{PROJECT}.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }


def _project(paths: BoxPaths, volumes: list) -> Path:
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(_manifest()))
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.27-alpine", "volumes": volumes,
    }}}))
    return project_dir


# ---------------------------------------------------------------------------
# (b) Root re-runs `up` on files and bind sources a container could change
# ---------------------------------------------------------------------------


@pytest.fixture
def compose_commands(monkeypatch) -> list[list[str]]:
    """Run every docker command for real except `up` and `start`, which are
    recorded instead, so no container is started."""
    issued: list[list[str]] = []
    real = docker._run

    def run(cmd, *args, **kwargs):
        if "up" in cmd or "start" in cmd:
            issued.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return real(cmd, *args, **kwargs)

    monkeypatch.setattr(docker, "_run", run)
    return issued


@pytest.fixture
def alerts(monkeypatch) -> list[str]:
    sent: list[str] = []
    monkeypatch.setattr(
        "boxmunge.notify.send_notification",
        lambda user, token, title, body, priority=0: sent.append(f"{title}: {body}") or True)
    return sent


def _upgrade(paths: BoxPaths) -> None:
    """The root half of `upgrade --apply`: regenerate configs, restart, and
    alert for the projects regeneration refused."""
    from boxmunge.commands.upgrade_steps import (
        notify_refused, regenerate_configs, restart_projects,
    )
    regen = regenerate_configs(paths)
    restart_projects(paths, refused=regen.refused)
    notify_refused(paths, regen.refused)


def _deployed(paths: BoxPaths, compose_commands: list) -> Path:
    """A project with a data/uploads bind mount, restarted once by an upgrade."""
    project_dir = _project(paths, ["./data/uploads:/uploads"])
    (project_dir / "data" / "uploads").mkdir(parents=True)
    _upgrade(paths)
    assert [c for c in compose_commands if "up" in c], "an untampered project restarts"
    compose_commands.clear()
    return project_dir


def test_upgrade_restart_runs_up_on_an_untampered_project(tmp_path, compose_commands, alerts) -> None:
    paths = _paths(tmp_path)
    _deployed(paths, compose_commands)
    _upgrade(paths)
    assert [c for c in compose_commands if "up" in c]
    assert alerts == []


def test_upgrade_restart_refuses_a_bind_source_swapped_for_a_symlink(
    tmp_path, compose_commands, alerts,
) -> None:
    paths = _paths(tmp_path)
    project_dir = _deployed(paths, compose_commands)
    host = tmp_path / "host-root"
    host.mkdir()
    # What a container that can write data/ does to the uploads mount.
    shutil.rmtree(project_dir / "data" / "uploads")
    os.symlink(host, project_dir / "data" / "uploads")

    _upgrade(paths)

    assert compose_commands == []
    assert alerts and "outside the project" in alerts[0]


def test_upgrade_restart_refuses_a_bind_source_redirected_inside_the_project(
    tmp_path, compose_commands, alerts,
) -> None:
    """A link to another directory of the project passes the path rules;
    the no-follow walk still refuses it."""
    paths = _paths(tmp_path)
    project_dir = _deployed(paths, compose_commands)
    (project_dir / "media").mkdir()
    shutil.rmtree(project_dir / "data" / "uploads")
    os.symlink("../media", project_dir / "data" / "uploads")

    _upgrade(paths)

    assert compose_commands == []
    assert alerts and "data/uploads is a symlink" in alerts[0]


def test_upgrade_restart_refuses_a_parent_of_a_bind_source_swapped_for_a_symlink(
    tmp_path, compose_commands, alerts,
) -> None:
    paths = _paths(tmp_path)
    project_dir = _deployed(paths, compose_commands)
    host = tmp_path / "host-root"
    (host / "uploads").mkdir(parents=True)
    shutil.rmtree(project_dir / "data")
    os.symlink(host, project_dir / "data")

    _upgrade(paths)

    assert compose_commands == []
    assert alerts and "outside the project" in alerts[0]


def test_upgrade_restart_refuses_a_compose_file_rewritten_after_deploy(
    tmp_path, compose_commands, alerts,
) -> None:
    paths = _paths(tmp_path)
    project_dir = _deployed(paths, compose_commands)
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx:1.27-alpine", "privileged": True, "volumes": ["/:/host"],
    }}}))

    _upgrade(paths)

    assert compose_commands == []
    assert alerts and PROJECT in alerts[0]


def test_provider_project_is_refused_before_any_host_exec(tmp_path, alerts) -> None:
    """A compose `provider` whose type is a container-writable script: the
    guard refuses before `docker compose up`, so the script never runs on
    the host as root (review 67 blocker). Real `docker compose config`."""
    from boxmunge.compose_guard import ComposeRefused, compose_up_checked
    paths = _paths(tmp_path)
    project_dir = paths.project_dir(PROJECT)
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "data").mkdir()
    marker = tmp_path / "ran-on-host"
    (project_dir / "data" / "evil").write_text(f"#!/bin/sh\ntouch {marker}\n")
    os.chmod(project_dir / "data" / "evil", 0o755)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump(_manifest()))
    (project_dir / "compose.yml").write_text(yaml.safe_dump({"services": {
        "web": {"image": "nginx:1.27-alpine", "network_mode": "none",
                "read_only": True, "volumes": ["./data:/d"]},
        "thing": {"provider": {"type": "./data/evil", "options": {"a": "b"}}},
    }}))
    with pytest.raises(ComposeRefused, match="provider"):
        compose_up_checked(paths, PROJECT, component="upgrade",
                           compose_files=["compose.yml"], build=False)
    assert not marker.exists()
    assert alerts and "provider" in alerts[0]


def test_legacy_container_mounting_the_project_rw_is_refused(tmp_path, compose_commands, alerts) -> None:
    """A project deployed before these rules whose running container mounts
    the project directory read-write: its bind record would bless that
    mount, so the guard inspects the real container and refuses, requiring a
    redeploy (review 67 blocker 2a). Starts one real throwaway container."""
    from boxmunge import bind_sources
    from boxmunge.commands.upgrade_steps import restart_projects
    paths = _paths(tmp_path)
    project_dir = _project(paths, [".:/app"])  # a legacy read-write project-dir mount
    # Record as if an older deploy had (the rule did not exist then).
    bind_sources.record(project_dir, {"."}, [], paths.project_bind_record(PROJECT))
    compose_project = PROJECT
    try:
        subprocess.run(
            ["docker", "run", "-d", "--name", f"{compose_project}-web-1",
             "--label", f"com.docker.compose.project={compose_project}",
             "--label", "com.docker.compose.service=web",
             "--network", "none", "-v", f"{project_dir}:/app",
             "busybox:1.36", "sleep", "600"],
            check=True, capture_output=True, timeout=120)
        compose_commands.clear()
        restart_projects(paths, refused=())
        assert compose_commands == []
        assert alerts and "redeploy" in alerts[0]
    finally:
        subprocess.run(["docker", "rm", "-f", f"{compose_project}-web-1"],
                       capture_output=True, timeout=60)
