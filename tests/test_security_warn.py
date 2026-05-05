"""Tests for boxmunge.security_warn — deploy-time warning emitter."""
from __future__ import annotations

import io
import json
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

    @pytest.mark.parametrize(
        "component", ["deploy", "stage", "promote", "resume", "upgrade"],
    )
    def test_component_passed_to_log(self, fake_paths, component: str) -> None:
        """Component string must flow through to the JSON log entry.

        Note: `promote` currently logs as `component="promote"` here because
        warn_off_services receives the component arg directly. The audit-G-1
        finding (`promote` callsite passes "deploy") is a Phase 6 fix; this
        test asserts the *flow* of the component arg, not the upstream caller.
        """
        manifest = {
            "project": "demo",
            "security": {"profile": "off", "reason": "x"},
            "services": {"web": {"port": 3000}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_off_services(fake_paths, manifest, component=component)
        assert "SECURITY OFF" in buf.getvalue()
        # Inspect the JSON log file: component field must equal the arg.
        entries = [
            json.loads(line)
            for line in fake_paths.log_file.read_text().strip().splitlines()
            if line
        ]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["component"] == component
        assert entry["project"] == "demo"
        assert entry["level"] == "warn"

    def test_structured_detail_event_field(self, fake_paths) -> None:
        """Operators filter on detail.event=security_off — must be set."""
        manifest = {
            "project": "demo",
            "security": {"profile": "off", "reason": "deliberate"},
            "services": {"web": {"port": 3000}, "worker": {"port": 4000}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_off_services(fake_paths, manifest, component="deploy")
        entries = [
            json.loads(line)
            for line in fake_paths.log_file.read_text().strip().splitlines()
            if line
        ]
        # One entry per (service, reason) pair.
        assert len(entries) == 2
        for entry in entries:
            detail = entry["detail"]
            assert detail["event"] == "security_off"
            assert detail["reason"] == "deliberate"
            assert detail["service"] in {"web", "worker"}
        services_logged = {e["detail"]["service"] for e in entries}
        assert services_logged == {"web", "worker"}
