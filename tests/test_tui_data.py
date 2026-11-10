"""Tests for boxmunge.tui.data — TUI data loading functions."""

import subprocess
from datetime import datetime, timezone

import pytest

from boxmunge.tui.data import (
    load_all_project_status,
    load_host_info,
    load_project_backups,
    load_project_services,
    relative_time,
)
from boxmunge.paths import BoxPaths
from boxmunge.state import write_state


def _create_project(paths: BoxPaths, name: str) -> None:
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(
        f"project: {name}\nrepo: ''\nref: main\nhosts:\n  - {name}.example.com\n"
        f"services:\n  web:\n    type: frontend\n    port: 3000\n    routes:\n      - path: /\n"
        f"backup:\n  type: none\nenv_files: []\n"
    )
    (pdir / "backups").mkdir()


class TestLoadAllProjectStatus:
    def test_returns_empty_for_no_projects(self, paths: BoxPaths) -> None:
        result = load_all_project_status(paths)
        assert result == []

    def test_returns_status_for_projects(self, paths: BoxPaths) -> None:
        _create_project(paths, "alpha")
        _create_project(paths, "beta")
        write_state(paths.project_health_state("alpha"), {
            "status": "ok",
            "last_check": "2026-03-30T10:00:00Z",
            "failure_reason": "",
        })
        write_state(paths.project_deploy_state("alpha"), {
            "current_ref": "abc123",
            "deployed_at": "2026-03-28T10:00:00Z",
        })

        result = load_all_project_status(paths)
        assert len(result) == 2
        alpha = next(p for p in result if p.name == "alpha")
        assert alpha.status == "ok"
        assert alpha.current_ref == "abc123"

    def test_unknown_status_when_no_state(self, paths: BoxPaths) -> None:
        _create_project(paths, "newapp")
        result = load_all_project_status(paths)
        assert len(result) == 1
        assert result[0].status == "unknown"
        assert result[0].current_ref == ""


@pytest.mark.usefixtures("docker_down")  # the host panel asks Docker whether Caddy runs
class TestLoadHostInfo:
    def test_loads_hostname_from_config(self, paths: BoxPaths) -> None:
        config_file = paths.config_file
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("hostname: testbox\nadmin_email: a@b.com\n")
        info = load_host_info(paths)
        assert info.hostname == "testbox"
        assert info.disk_free_gb > 0

    def test_fallback_when_no_config(self, paths: BoxPaths) -> None:
        info = load_host_info(paths)
        assert info.hostname == "unknown"


class TestPolledDockerCalls:
    """The console polls every 10 s: it parses no compose file and asks
    Docker once, not once per service (deep review E-6)."""

    def test_caddy_running_comes_from_its_compose_labels(self, paths, fake_containers) -> None:
        assert load_host_info(paths).caddy_running is False
        fake_containers.run("caddy", "caddy", "sha256:" + "c" * 64, name="boxmunge-caddy")
        assert load_host_info(paths).caddy_running is True

    def test_service_health_is_one_docker_inspect(self, paths, monkeypatch) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(
            "project: myapp\nhosts: [myapp.example.com]\nservices:\n"
            "  web: {port: 3000, routes: [{path: /}]}\n  api: {port: 4000, routes: []}\n"
            "  worker: {port: 5000, routes: []}\n")
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(
                cmd, 1, "/myapp-web-1\thealthy\n/myapp-api-1\t\n",
                "Error: No such object: myapp-worker-1")

        monkeypatch.setattr(subprocess, "run", run)
        services = {s.name: s.docker_health for s in load_project_services(paths, "myapp")}
        assert services == {"web": "healthy", "api": None, "worker": None}
        assert len(calls) == 1
        assert calls[0][-3:] == ["myapp-web-1", "myapp-api-1", "myapp-worker-1"]


class TestLoadProjectBackups:
    def test_lists_backups(self, paths: BoxPaths) -> None:
        _create_project(paths, "myapp")
        bdir = paths.project_backups("myapp")
        (bdir / "myapp-2026-03-28T020000.tar.gz.age").write_bytes(b"aaa")
        (bdir / "myapp-2026-03-29T020000.tar.gz.age").write_bytes(b"bbbbb")

        result = load_project_backups(paths, "myapp")
        assert len(result) == 2
        assert result[0].size_bytes == 5  # newest first, larger file


class TestRelativeTime:
    def test_recent(self) -> None:
        now = datetime.now(timezone.utc)
        ts = now.isoformat()
        result = relative_time(ts)
        assert "just now" in result or "0m" in result or "s" in result

    def test_empty_string(self) -> None:
        assert relative_time("") == "-"

    def test_dash(self) -> None:
        assert relative_time("-") == "-"
