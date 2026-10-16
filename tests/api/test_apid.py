# SPDX-License-Identifier: Apache-2.0
"""boxmunge-apid: the dev-mode command line, end to end over a real socket."""
from __future__ import annotations

import ast
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from boxmunge.api.apid import build_dev_app, main
from boxmunge.api.dev.fixture import FIXTURE_MARKER, make_fixture
from tests.api.unix_http import call

REPO = Path(__file__).resolve().parents[2]


def test_make_fixture_command(tmp_path, capsys) -> None:
    main(["--make-fixture", str(tmp_path / "box")])
    assert (tmp_path / "box" / FIXTURE_MARKER).is_file()
    assert "Serve it with: boxmunge-apid --dev" in capsys.readouterr().out


def test_make_fixture_refuses_a_used_directory(tmp_path, capsys) -> None:
    (tmp_path / "box").mkdir()
    (tmp_path / "box" / "notes.txt").write_text("mine")
    with pytest.raises(SystemExit) as excinfo:
        main(["--make-fixture", str(tmp_path / "box")])
    assert excinfo.value.code == 1
    assert "not an empty directory" in capsys.readouterr().err


def test_dev_mode_refuses_a_real_box(paths, sock_path, capsys) -> None:
    paths.config_file.write_text("hostname: real.example.test\nadmin_email: a@b.test\n")
    with pytest.raises(SystemExit) as excinfo:
        main(["--dev", "--root", str(paths.root), "--socket", str(sock_path)])
    assert excinfo.value.code == 1
    assert "is not a fixture box" in capsys.readouterr().err
    assert not sock_path.exists()


@pytest.mark.parametrize("argv", [
    [], ["--dev"], ["--dev", "--root", "x"],
    ["--make-fixture", "x", "--socket", "y"], ["--dev", "--make-fixture", "x"],
])
def test_usage_errors_exit_2(argv) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == 2


def test_bad_plugin_name_is_refused(tmp_path, sock_path, capsys) -> None:
    make_fixture(tmp_path / "box")
    with pytest.raises(SystemExit):
        main(["--dev", "--root", str(tmp_path / "box"), "--socket", str(sock_path),
              "--plugin", "Web UI"])
    assert "invalid plugin name" in capsys.readouterr().err


def test_dev_app_serves_observe_as_the_named_plugin(tmp_path) -> None:
    make_fixture(tmp_path / "box")
    status, body = build_dev_app(tmp_path / "box", "webui").handle("GET", "/v1/actions", None)
    assert status == 200 and body["data"]["principal"] == "plugin:webui"
    assert {entry["tier"] for entry in body["data"]["actions"]} == {"observe"}


def _wait_for_socket(path: Path, proc: subprocess.Popen) -> None:
    for _ in range(200):
        if proc.poll() is not None:
            pytest.fail(f"apid exited early: {proc.stderr.read().decode()}")
        if path.exists():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                try:
                    probe.connect(str(path))
                    return
                except ConnectionRefusedError:
                    pass
        time.sleep(0.05)
    pytest.fail("apid did not start listening")


def test_dev_apid_end_to_end(tmp_path, sock_path) -> None:
    root = tmp_path / "box"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    apid = [sys.executable, "-m", "boxmunge.api.apid"]
    subprocess.run([*apid, "--make-fixture", str(root)], env=env, check=True,
                   capture_output=True)
    proc = subprocess.Popen([*apid, "--dev", "--root", str(root), "--socket", str(sock_path),
                             "--plugin", "webui"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _wait_for_socket(sock_path, proc)
        status, catalog = call(sock_path, "GET", "/v1/actions")
        assert status == 200 and catalog["data"]["principal"] == "plugin:webui"
        status, body = call(sock_path, "POST", "/v1/actions/status.get", {"params": {}})
        assert status == 200 and len(body["data"]["projects"]) == 5
        status, body = call(sock_path, "POST", "/v1/actions/project.rollback",
                            {"params": {"project": "shop"}})
        assert status == 404 and body["error"]["code"] == "not_found"
    finally:
        proc.send_signal(signal.SIGTERM)
        _, stderr = proc.communicate(timeout=10)
    assert proc.returncode == 0, stderr.decode()
    assert b"DEV MODE" in stderr
    assert not sock_path.exists()
    audit = [json.loads(line) for line in (root / "logs" / "audit.jsonl").read_text().splitlines()]
    assert [(r["principal"], r["action"], r["outcome"], r["code"]) for r in audit] == [
        ("plugin:webui", "project.rollback", "refused", "not_found")]


def test_phase_a_installs_no_apid_service() -> None:
    assert "apid" not in (REPO / "install.sh").read_text()
    assert [p.name for p in (REPO / "systemd").iterdir() if "apid" in p.name] == []


def test_pyproject_declares_the_entry_point() -> None:
    assert 'boxmunge-apid = "boxmunge.api.apid:main"' in (REPO / "pyproject.toml").read_text()


def _imports_of_the_api(path: Path) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module] + [f"{node.module}.{alias.name}" for alias in node.names]
        else:
            continue
        found += [f"{path.name}:{node.lineno} {name}" for name in names
                  if name == "boxmunge.api" or name.startswith("boxmunge.api.")]
    return found


def test_nothing_outside_the_api_package_imports_it() -> None:
    """Phase A ships inert: no CLI command, shell, MCP tool or timer routes
    through boxmunge.api, so production boxes behave exactly as before. The
    only way in is the boxmunge-apid console script. Update this
    deliberately when a frontend converts."""
    src = REPO / "src" / "boxmunge"
    outside = [p for p in src.rglob("*.py") if (src / "api") not in p.parents]
    assert len(outside) > 50
    assert [hit for module in outside for hit in _imports_of_the_api(module)] == []
    for module in ("cli.py", "shell.py", "mcp_server.py", "mcp_tools.py"):
        assert "apid" not in (src / module).read_text(), module
