"""Tests for boxmunge.tui.data — TUI data loading functions."""

import pytest
from pathlib import Path
from datetime import datetime, timezone

from boxmunge.tui.data import (
    ProjectStatus,
    HostInfo,
    BackupInfo,
    load_all_project_status,
    load_host_info,
    load_project_backups,
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
