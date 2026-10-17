# SPDX-License-Identifier: Apache-2.0
"""Tests for boxmunge doctor command — host health diagnostic."""

import json
import sys

import pytest

from boxmunge.commands.doctor import cmd_doctor
from boxmunge.paths import BoxPaths

# Doctor probes the docker CLI (Compose version, the system container, Caddy).
pytestmark = pytest.mark.usefixtures("docker_down")


class TestDoctorJson:
    """Audit H-5: `--json` must suppress the banner so output stays parseable."""

    def test_json_output_is_parseable(
        self, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            "boxmunge.commands.doctor.BoxPaths", lambda: paths,
        )
        with pytest.raises(SystemExit):
            cmd_doctor(["--json"])
        out = capsys.readouterr().out
        # No banner pollution: the entire stdout must parse as JSON.
        payload = json.loads(out)
        assert isinstance(payload, list)
        # Each result has the documented shape
        for r in payload:
            assert {"name", "status", "detail"} <= r.keys()

    def test_text_output_includes_banner(
        self, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            "boxmunge.commands.doctor.BoxPaths", lambda: paths,
        )
        with pytest.raises(SystemExit):
            cmd_doctor([])
        out = capsys.readouterr().out
        assert "boxmunge doctor" in out


class TestDoctorUnknownArg:
    """Audit H-N1: cmd_doctor rejects unknown flags."""

    def test_unknown_flag_exits_2(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            cmd_doctor(["--not-a-flag"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "--not-a-flag" in err


class TestDoctorTimers:
    def test_checks_every_shipped_timer(self, paths: BoxPaths, monkeypatch) -> None:
        """doctor checked three of the six timers install.sh enables."""
        import subprocess
        from pathlib import Path
        from boxmunge.commands.doctor import run_doctor

        asked: list[str] = []
        real_run = subprocess.run

        def fake_run(cmd, *args, **kwargs):
            if cmd[:2] == ["systemctl", "is-active"]:
                asked.append(cmd[2])
                return subprocess.CompletedProcess(cmd, 0, stdout="active\n", stderr="")
            return real_run(cmd, *args, **kwargs)

        monkeypatch.setattr("boxmunge.commands.doctor.subprocess.run", fake_run)
        run_doctor(paths, as_json=True)
        shipped = {p.name for p in (Path(__file__).parents[2] / "systemd").glob("*.timer")}
        assert set(asked) >= shipped


class TestDoctorComposeVersion:
    def test_old_compose_fails_doctor(self, paths: BoxPaths, monkeypatch, capsys) -> None:
        from boxmunge.commands.doctor import run_doctor
        monkeypatch.setattr("boxmunge.compose_version.compose_version_problem",
                            lambda: "Docker Compose 2.34.0 is older than 2.35.0")
        monkeypatch.setattr("boxmunge.commands.doctor.shutil.which", lambda _: "/usr/bin/docker")
        assert run_doctor(paths, as_json=True) == 1
        results = {r["name"]: r for r in json.loads(capsys.readouterr().out)}
        line = results["Docker Compose version supported"]
        assert line["status"] == "FAIL"
        assert "older than 2.35.0" in line["detail"]


class TestDoctorMcp:
    """MCP is part of every install; an environment without it is broken."""

    def _mcp_line(self, paths: BoxPaths, capsys) -> dict:
        from boxmunge.commands.doctor import run_doctor
        run_doctor(paths, as_json=True)
        return {r["name"]: r for r in json.loads(capsys.readouterr().out)}["MCP package installed"]

    def test_missing_mcp_fails_doctor_with_the_repair(self, paths: BoxPaths, monkeypatch, capsys) -> None:
        monkeypatch.setitem(sys.modules, "mcp", None)
        line = self._mcp_line(paths, capsys)
        assert line["status"] == "FAIL"
        assert "boxmunge-install.sh" in line["detail"]

    def test_installed_mcp_passes(self, paths: BoxPaths, monkeypatch, capsys) -> None:
        monkeypatch.setattr("boxmunge.commands.mcp_serve_cmd.mcp_import_error", lambda: None)
        assert self._mcp_line(paths, capsys)["status"] == "PASS"
