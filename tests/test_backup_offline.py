"""A dump over a stopped service's data runs in a one-off container, offline."""
from __future__ import annotations

import subprocess

import pytest

from boxmunge import backup_offline
from boxmunge.backup import BackupError
from boxmunge.compose_guard import ComposeRefused


@pytest.fixture
def run(paths, monkeypatch):
    paths.project_dir("shop").mkdir(parents=True)
    seen: dict = {"checks": [], "removed": []}
    monkeypatch.setattr(backup_offline, "check_start",
                        lambda *a, **k: seen["checks"].append(k["compose_files"]))
    monkeypatch.setattr(backup_offline, "resolve_deployed_config",
                        lambda *a, **k: {"services": {"app": {"image": "shop-app:1"}}})
    monkeypatch.setattr(backup_offline, "absent_images", lambda images: [])
    monkeypatch.setattr(backup_offline, "_run",
                        lambda cmd, **k: seen["removed"].append(cmd[-1]))

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["overlay"] = open(cmd[cmd.index("-f", cmd.index("compose.boxmunge.yml")) + 1]
                               ).read()
        if seen.get("timeout"):
            raise subprocess.TimeoutExpired(cmd, 1)
        return subprocess.CompletedProcess(cmd, 0, b"dump", b"")
    monkeypatch.setattr(backup_offline.subprocess, "run", fake_run)
    return seen


def test_the_dump_runs_once_offline_as_the_service_without_starting_it(paths, run) -> None:
    result = backup_offline.run_offline(paths, "shop", "app", "sqlite3 /d/db .dump",
                                        timeout=10, component="data-chown")
    assert result.stdout == b"dump"
    assert run["checks"] == [["compose.yml", "compose.boxmunge.yml"]]
    cmd = run["cmd"]
    tail = cmd[cmd.index("run"):]
    assert tail[:6] == ["run", "--rm", "--no-deps", "-T", "--pull", "never"]
    assert tail[-5:] == ["--entrypoint", "sh", "app", "-c", "sqlite3 /d/db .dump"]
    assert "-u" not in tail and "--user" not in tail      # the service's own user
    assert "network_mode: none" in run["overlay"]
    assert "networks: !reset null" in run["overlay"] and "ports: !reset []" in run["overlay"]


def test_a_refused_start_check_is_a_backup_error(paths, run, monkeypatch) -> None:
    def refuse(*a, **k):
        raise ComposeRefused("Refused to start shop: an install is open")
    monkeypatch.setattr(backup_offline, "check_start", refuse)
    with pytest.raises(BackupError, match="cannot start: Refused to start shop"):
        backup_offline.run_offline(paths, "shop", "app", "dump", timeout=10, component="c")
    assert "cmd" not in run


def test_a_missing_image_is_refused_not_built(paths, run, monkeypatch) -> None:
    monkeypatch.setattr(backup_offline, "absent_images", lambda images: [("app", "shop-app:1")])
    with pytest.raises(BackupError, match="not in the local image store"):
        backup_offline.run_offline(paths, "shop", "app", "dump", timeout=10, component="c")
    assert "cmd" not in run


def test_an_overrun_removes_the_one_off(paths, run) -> None:
    run["timeout"] = True
    with pytest.raises(BackupError, match="timed out after 10s; its one-off container"):
        backup_offline.run_offline(paths, "shop", "app", "dump", timeout=10, component="c")
    assert len(run["removed"]) == 1 and run["removed"][0].startswith("shop-app-dump-")
