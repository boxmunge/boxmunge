# SPDX-License-Identifier: Apache-2.0
"""Which ssh and scp call gets the CLI's own stdin, in a real process.

In-process tests cannot show this: a subprocess inherits file descriptor 0,
not a monkeypatched sys.stdin. Real ssh forwards whatever its stdin holds to
the remote command, so a call that inherits it consumes it: a piped secret
read by the handshake never reached `secrets set`.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from boxmunge_cli.init_cmd import run_init

SRC = Path(__file__).resolve().parent.parent / "src"


@pytest.fixture
def project(tmp_path: Path, fake_remote) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", host="myapp.example.com") == 0
    fake_remote.respond("ssh", "handshake", stdout=json.dumps({
        "server_version": "0.11.5", "min_client_version": "0.1.0", "schema_version": 3}))
    return root


def run_piped(project: Path, argv: list[str], piped: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    return subprocess.run(
        [sys.executable, "-c", "import sys; from boxmunge_cli.cli import main; "
                               "main(sys.argv[1:])", *argv],
        input=piped, text=True, capture_output=True, cwd=project, env=env, check=False)


def _stdins(fake_remote) -> list[tuple[str, str | None]]:
    entries = [json.loads(line) for line in fake_remote.log.read_text().splitlines()]
    return [(" ".join(e["argv"][-1:]), e["stdin"]) for e in entries]


def test_a_piped_secret_reaches_secrets_set_not_the_handshake(project, fake_remote) -> None:
    result = run_piped(project, ["secrets", "set", "API_KEY"], "s3cret\n")
    assert result.returncode == 0, result.stderr
    assert _stdins(fake_remote) == [("handshake", ""),
                                    ("secrets set myapp API_KEY", "s3cret\n")]


@pytest.mark.parametrize("argv", [["prod-deploy"], ["stage"], ["status"], ["logs"],
                                  ["validate"], ["secrets", "list"], ["rollback", "--yes"],
                                  ["prod-deploy", "--redeploy"]])
def test_commands_that_send_nothing_give_ssh_and_scp_no_stdin(project, fake_remote,
                                                              argv) -> None:
    result = run_piped(project, argv, "not for the server\n")
    assert result.returncode == 0, result.stderr
    stdins = _stdins(fake_remote)
    assert len(stdins) >= 2
    assert all(stdin == "" for _, stdin in stdins), stdins


def test_remote_passes_stdin_to_its_command_only(project, fake_remote) -> None:
    result = run_piped(project, ["remote", "secrets", "set", "myapp", "API_KEY"], "s3cret\n")
    assert result.returncode == 0, result.stderr
    assert _stdins(fake_remote) == [("handshake", ""),
                                    ("secrets set myapp API_KEY", "s3cret\n")]


def test_mcp_serve_keeps_the_hosts_first_message_for_the_proxy(project, fake_remote) -> None:
    result = run_piped(project, ["mcp-serve"], '{"jsonrpc": "2.0"}\n')
    assert result.returncode == 0, result.stderr
    assert _stdins(fake_remote) == [("handshake", ""), ("mcp-serve", '{"jsonrpc": "2.0"}\n')]
