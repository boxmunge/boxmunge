"""Tests for boxmunge.security_warn — deploy-time warning emitter."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import pytest

from boxmunge.security_warn import warn_off_services, warn_writable_state


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

        Phase 6 (audit G-1) fixed the upstream caller chain so promote now
        passes ``component="promote"`` through ``run_deploy`` to
        ``warn_off_services``. The end-to-end test for that wiring lives in
        ``tests/test_commands/test_promote_cmd.py`` — this test only asserts
        that the component arg flows through ``warn_off_services``.
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


class TestWarnWritableState:
    """v0.9 deploy-time visibility for writable surface choices.

      - [WARNING] when user compose declares read_only: false (acknowledges
        the CVE hardening penalty)
      - [INFO] when manifest has writable.external: true (signals delegation)
    """

    def test_nothing_to_warn_emits_nothing(self, fake_paths) -> None:
        manifest = {
            "project": "demo",
            "services": {"web": {"port": 3000}},
        }
        user_compose = {"services": {"web": {"image": "nginx"}}}
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose, component="deploy",
            )
        assert buf.getvalue() == ""

    def test_read_only_false_emits_warning(self, fake_paths) -> None:
        manifest = {
            "project": "demo",
            "services": {"web": {"port": 3000}},
        }
        user_compose = {
            "services": {"web": {"image": "nginx", "read_only": False}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose, component="deploy",
            )
        out = buf.getvalue()
        assert "[WARNING]" in out
        assert "read_only: false" in out
        assert "demo/web" in out
        assert "CVE hardening penalty" in out

    def test_read_only_true_does_not_warn(self, fake_paths) -> None:
        """Only False fires the warning — True matches the baseline."""
        manifest = {
            "project": "demo",
            "services": {"web": {"port": 3000}},
        }
        user_compose = {
            "services": {"web": {"image": "nginx", "read_only": True}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose, component="deploy",
            )
        assert "[WARNING]" not in buf.getvalue()

    def test_external_writable_emits_info(self, fake_paths) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 3000,
                    "writable": {"external": True},
                },
            },
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose=None, component="deploy",
            )
        out = buf.getvalue()
        assert "[INFO]" in out
        assert "demo/web" in out
        assert "externally-managed" in out

    def test_managed_writable_does_not_info(self, fake_paths) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 3000,
                    "writable": {"ephemeral": ["/var/cache"]},
                },
            },
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose=None, component="deploy",
            )
        assert buf.getvalue() == ""

    def test_both_signals_coexist(self, fake_paths) -> None:
        """A service can have writable.external AND user compose's
        read_only: false — both signals must fire independently."""
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 3000,
                    "writable": {"external": True},
                },
            },
        }
        user_compose = {
            "services": {"web": {"image": "nginx", "read_only": False}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose, component="deploy",
            )
        out = buf.getvalue()
        assert "[WARNING]" in out
        assert "[INFO]" in out

    def test_structured_log_entries_for_both(self, fake_paths) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {"port": 3000},
                "api": {
                    "port": 8000,
                    "writable": {"external": True},
                },
            },
        }
        user_compose = {
            "services": {"web": {"image": "nginx", "read_only": False}},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose, component="deploy",
            )
        entries = [
            json.loads(line)
            for line in fake_paths.log_file.read_text().strip().splitlines()
            if line
        ]
        # Two structured entries: one warn, one info.
        events = {e["detail"]["event"] for e in entries}
        assert "read_only_false" in events
        assert "writable_external" in events
        # Levels match the spec:
        for entry in entries:
            if entry["detail"]["event"] == "read_only_false":
                assert entry["level"] == "warn"
            if entry["detail"]["event"] == "writable_external":
                assert entry["level"] == "info"

    @pytest.mark.parametrize(
        "component", ["deploy", "stage", "resume", "upgrade"],
    )
    def test_component_passed_to_log(self, fake_paths, component: str) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {"port": 3000, "writable": {"external": True}},
            },
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose=None, component=component,
            )
        entries = [
            json.loads(line)
            for line in fake_paths.log_file.read_text().strip().splitlines()
            if line
        ]
        assert len(entries) == 1
        assert entries[0]["component"] == component
        assert entries[0]["project"] == "demo"

    def test_user_compose_none_safe(self, fake_paths) -> None:
        """Caller may pass None when no user compose exists. Manifest-only
        signals (external) still fire; read_only: false signals don't."""
        manifest = {
            "project": "demo",
            "services": {
                "web": {"port": 3000, "writable": {"external": True}},
            },
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            warn_writable_state(
                fake_paths, manifest, user_compose=None, component="deploy",
            )
        assert "[INFO]" in buf.getvalue()
        assert "[WARNING]" not in buf.getvalue()
