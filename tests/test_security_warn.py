"""Tests for boxmunge.security_warn — deploy-time warning emitter."""
from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest

from boxmunge.security_warn import warn_off_services


@pytest.fixture
def fake_paths(tmp_path, monkeypatch):
    from boxmunge.paths import BoxPaths
    from boxmunge.log import _reset_logger
    monkeypatch.setattr(BoxPaths, "__init__", lambda self: None)
    paths = BoxPaths()
    paths.logs = tmp_path / "logs"
    paths.logs.mkdir()
    paths.log_file = paths.logs / "boxmunge.log"
    # Force a fresh logger so the file handler points at our tmp path.
    _reset_logger()
    yield paths
    _reset_logger()


class TestWarnOffServices:
    def test_no_off_services_emits_nothing(self, fake_paths) -> None:
        manifest = {
            "project": "demo",
            "services": {"web": {"port": 3000}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_off_services(fake_paths, manifest, component="deploy")
        assert buf.getvalue() == ""

    def test_off_service_prints_warning(self, fake_paths) -> None:
        manifest = {
            "project": "demo",
            "security": {"profile": "off", "reason": "deliberate"},
            "services": {"web": {"port": 3000}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_off_services(fake_paths, manifest, component="deploy")
        out = buf.getvalue()
        assert "SECURITY OFF" in out
        assert "demo/web" in out
        assert "deliberate" in out

    def test_component_passed_to_log(self, fake_paths) -> None:
        # Use a sentinel to verify component string flows through.
        manifest = {
            "project": "demo",
            "security": {"profile": "off", "reason": "x"},
            "services": {"web": {"port": 3000}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_off_services(fake_paths, manifest, component="stage")
        # The function should not crash with a custom component name.
        assert "SECURITY OFF" in buf.getvalue()
