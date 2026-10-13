"""Tests for the MCP stdio proxy: configuration, handshake, transparent pipe."""

from pathlib import Path

import pytest

from boxmunge_cli.cli import main
from boxmunge_cli.mcp_proxy import run_mcp_proxy

CONFIG = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}


def run_cli(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


def test_pipe_runs_mcp_serve_in_batch_mode(fake_remote, capfd) -> None:
    fake_remote.respond("ssh", "mcp-serve", stdout='{"jsonrpc": "2.0"}\n', rc=7)
    assert run_mcp_proxy(CONFIG) == 7
    [argv] = fake_remote.calls("ssh")
    assert argv[-1] == "mcp-serve" and "BatchMode=yes" in argv
    # The server's output reaches our stdout untouched.
    assert capfd.readouterr().out == '{"jsonrpc": "2.0"}\n'


def test_server_flags_need_no_project(tmp_path: Path, monkeypatch, fake_remote, capfd) -> None:
    monkeypatch.chdir(tmp_path)  # no .boxmunge anywhere near
    assert run_cli(["mcp-serve", "--server", "box.example.com", "--port", "2222"]) == 0
    calls = fake_remote.calls("ssh")
    assert [c[-1] for c in calls] == ["handshake", "mcp-serve"]
    for argv in calls:
        assert "deploy@box.example.com" in argv and "2222" in argv and "BatchMode=yes" in argv
    assert capfd.readouterr().out == ""  # handshake output never reaches the MCP host


def test_config_path(tmp_path: Path, monkeypatch, fake_remote) -> None:
    cfg = tmp_path / "conf" / ".boxmunge"
    cfg.parent.mkdir()
    cfg.write_text("server: other.example.com\nproject: myapp\n")
    monkeypatch.chdir(tmp_path)
    assert run_cli(["mcp-serve", "--config", str(cfg)]) == 0
    assert "deploy@other.example.com" in fake_remote.calls("ssh")[-1]


def test_failed_handshake_never_starts_the_pipe(tmp_path, monkeypatch, fake_remote,
                                                capfd) -> None:
    monkeypatch.chdir(tmp_path)
    fake_remote.respond("ssh", "handshake", stderr="Permission denied (publickey).\n", rc=255)
    assert run_cli(["mcp-serve", "--server", "box.example.com"]) == 1
    assert [c[-1] for c in fake_remote.calls("ssh")] == ["handshake"]
    captured = capfd.readouterr()
    assert captured.out == "" and "Permission denied" in captured.err


@pytest.mark.parametrize("argv", [["mcp-serve", "--port", "22"],
                                  ["mcp-serve", "--server", "bad;host"],
                                  ["mcp-serve", "--server", "a.example.com", "--config", "x"]])
def test_bad_connection_options(tmp_path, monkeypatch, fake_remote, argv) -> None:
    monkeypatch.chdir(tmp_path)
    assert run_cli(argv) in (1, 2)
    assert fake_remote.calls() == []
