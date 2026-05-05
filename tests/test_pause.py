"""Tests for pause state primitives."""
import json
from pathlib import Path

from boxmunge.paths import BoxPaths
from boxmunge.pause import (
    is_paused, write_paused_state, clear_paused_state, read_paused_state,
)


def _setup(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    (paths.root / "state" / "deploy").mkdir(parents=True)
    return paths


class TestIsPaused:
    def test_false_when_no_file(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        assert is_paused("myapp", paths) is False

    def test_true_when_file_exists(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        paths.project_paused_state("myapp").write_text("{}")
        assert is_paused("myapp", paths) is True


class TestWritePausedState:
    def test_writes_paused_at_iso_timestamp(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        write_paused_state("myapp", paths)
        data = json.loads(paths.project_paused_state("myapp").read_text())
        assert "paused_at" in data
        assert "T" in data["paused_at"]
        assert any(c in data["paused_at"] for c in ("Z", "+", "-"))

    def test_writes_optional_reason(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        write_paused_state("myapp", paths, reason="post-incident")
        data = json.loads(paths.project_paused_state("myapp").read_text())
        assert data["reason"] == "post-incident"

    def test_omits_reason_when_not_given(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        write_paused_state("myapp", paths)
        data = json.loads(paths.project_paused_state("myapp").read_text())
        assert "reason" not in data


class TestClearPausedState:
    def test_removes_file(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        write_paused_state("myapp", paths)
        assert is_paused("myapp", paths)
        clear_paused_state("myapp", paths)
        assert not is_paused("myapp", paths)

    def test_idempotent_when_already_clear(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        # Should not raise.
        clear_paused_state("myapp", paths)


class TestReadPausedState:
    def test_returns_data(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        write_paused_state("myapp", paths, reason="x")
        data = read_paused_state("myapp", paths)
        assert data["reason"] == "x"

    def test_returns_none_when_not_paused(self, tmp_path: Path) -> None:
        paths = _setup(tmp_path)
        assert read_paused_state("myapp", paths) is None


class TestRenderMaintenanceCaddyConfig:
    def test_includes_all_hosts(self) -> None:
        from boxmunge.pause import render_maintenance_caddy_config
        config = render_maintenance_caddy_config(["a.example.com", "b.example.com"])
        assert "a.example.com" in config
        assert "b.example.com" in config

    def test_serves_503_with_retry_after(self) -> None:
        from boxmunge.pause import render_maintenance_caddy_config
        config = render_maintenance_caddy_config(["a.example.com"])
        assert "503" in config
        assert "Retry-After" in config

    def test_uses_file_server_from_maintenance_dir(self) -> None:
        from boxmunge.pause import render_maintenance_caddy_config
        config = render_maintenance_caddy_config(["a.example.com"])
        assert "/etc/caddy/maintenance" in config
        assert "file_server" in config

    def test_raises_if_no_hosts(self) -> None:
        import pytest
        from boxmunge.pause import render_maintenance_caddy_config
        with pytest.raises(ValueError, match="at least one host"):
            render_maintenance_caddy_config([])

    def test_status_inside_file_server_block(self) -> None:
        from boxmunge.pause import render_maintenance_caddy_config
        config = render_maintenance_caddy_config(["a.example.com"])
        # Verify "status 503" appears, AND "respond" does NOT appear
        # (respond would short-circuit file_server).
        assert "status 503" in config
        assert "respond" not in config
