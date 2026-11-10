# SPDX-License-Identifier: Apache-2.0
"""secrets / rollback / validate / remote, through the real entry point."""

import io
import json
import shlex
from pathlib import Path

import pytest

from boxmunge_cli.cli import main
from boxmunge_cli.init_cmd import run_init


def run_cli(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


@pytest.fixture
def project(tmp_path: Path, monkeypatch, fake_remote) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", host="myapp.example.com") == 0
    monkeypatch.chdir(root)
    return root


def _server_argv(fake_remote) -> list[list[str]]:
    """Each ssh call's remote command, parsed the way the server's shell does."""
    return [shlex.split(argv[-1]) for argv in fake_remote.calls("ssh")
            if argv[-1] != "handshake"]


SERVER_0115 = json.dumps({"server_version": "0.11.5", "min_client_version": "0.1.0",
                          "schema_version": 3})


@pytest.fixture
def stdin_server(fake_remote, monkeypatch):
    """A server new enough to take a secret's value on stdin; ssh's stdin is recorded."""
    fake_remote.respond("ssh", "handshake", stdout=SERVER_0115)
    monkeypatch.setenv("FAKE_REMOTE_READ_STDIN", "1")
    return fake_remote


def test_secrets_set_sends_the_value_on_stdin_not_in_argv(project, stdin_server,
                                                          monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("p@ss word; $(x)\n"))
    assert run_cli(["secrets", "set", "API_KEY"]) == 0
    assert _server_argv(stdin_server) == [["secrets", "set", "myapp", "API_KEY"]]
    assert stdin_server.stdins("ssh")[-1] == "p@ss word; $(x)\n"
    assert not any("p@ss" in arg for argv in stdin_server.calls("ssh") for arg in argv)


def test_secrets_set_key_value_also_goes_on_stdin(project, stdin_server) -> None:
    assert run_cli(["secrets", "set", "API_KEY=s3cret"]) == 0
    assert _server_argv(stdin_server) == [["secrets", "set", "myapp", "API_KEY"]]
    assert stdin_server.stdins("ssh")[-1] == "s3cret\n"


def test_secrets_set_refuses_a_value_with_a_line_break(project, stdin_server, capsys) -> None:
    assert run_cli(["secrets", "set", "API_KEY=a\nB=1"]) == 2
    assert "line break" in capsys.readouterr().err
    assert stdin_server.calls() == []


@pytest.mark.parametrize("piped", ["first\nsecond\n", "first\nsecond", "first\n\n"])
def test_secrets_set_refuses_more_than_one_line_on_stdin(project, stdin_server, monkeypatch,
                                                          piped, capsys) -> None:
    """Only one trailing newline is the line's end; anything after it would
    be silently dropped, so it is refused as the server refuses it."""
    monkeypatch.setattr("sys.stdin", io.StringIO(piped))
    assert run_cli(["secrets", "set", "API_KEY"]) == 2
    assert "line break" in capsys.readouterr().err
    assert _server_argv(stdin_server) == []


def test_secrets_set_takes_a_value_without_a_trailing_newline(project, stdin_server,
                                                              monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("s3cret"))
    assert run_cli(["secrets", "set", "API_KEY"]) == 0
    assert stdin_server.stdins("ssh")[-1] == "s3cret\n"


def test_secrets_set_is_refused_by_an_older_server_before_the_value_is_sent(
        project, fake_remote, monkeypatch, capsys) -> None:
    """The fixture's server is 0.11.0: it would take the value only in argv."""
    monkeypatch.setattr("sys.stdin", io.StringIO("s3cret\n"))
    assert run_cli(["secrets", "set", "API_KEY"]) == 3
    assert _server_argv(fake_remote) == []
    err = capsys.readouterr().err
    assert "boxmunge-server 0.11.5" in err and "remote upgrade" in err


def test_secrets_list_get_unset(project, fake_remote) -> None:
    assert run_cli(["secrets", "list"]) == 0
    assert run_cli(["secrets", "get", "API_KEY"]) == 0
    assert run_cli(["secrets", "unset", "API_KEY"]) == 0
    assert _server_argv(fake_remote) == [["secrets", "list", "myapp"],
                                         ["secrets", "get", "myapp", "API_KEY"],
                                         ["secrets", "unset", "myapp", "API_KEY"]]


@pytest.mark.parametrize("argv", [["secrets", "get"], ["secrets", "set", "bad key"],
                                  ["secrets", "get", "A=1"], ["secrets", "list", "A"],
                                  ["secrets", "rotate"]])
def test_bad_secrets_usage(project, fake_remote, argv) -> None:
    assert run_cli(argv) == 2
    assert fake_remote.calls() == []


@pytest.fixture
def no_terminal(monkeypatch):
    monkeypatch.setattr("boxmunge_cli.confirming.have_terminal", lambda: False)


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.setattr("boxmunge_cli.confirming.have_terminal", lambda: True)


CONFIRMING = [["rollback"], ["remote", "pause", "myapp"], ["remote", "resume", "myapp"],
              ["remote", "recover", "myapp"], ["remote", "restore", "myapp", "snap"],
              ["remote", "inbox", "clean", "myapp"], ["remote", "project-delete", "myapp"]]


@pytest.mark.parametrize("argv", CONFIRMING)
def test_a_confirming_command_without_a_terminal_is_refused_before_ssh(
        project, fake_remote, no_terminal, argv, capsys) -> None:
    assert run_cli(argv) == 2
    assert fake_remote.calls() == []
    assert "--yes" in capsys.readouterr().err


@pytest.mark.parametrize("argv", CONFIRMING)
def test_a_confirming_command_at_a_terminal_lets_the_server_ask(
        project, fake_remote, terminal, argv) -> None:
    assert run_cli(argv) == 0
    (call,) = [a for a in fake_remote.calls("ssh") if a[-1] != "handshake"]
    assert "-t" in call[:-1]
    assert "--yes" not in shlex.split(call[-1])


@pytest.mark.parametrize("argv", [["remote", "pause", "myapp", "--yes"],
                                  ["remote", "resume", "myapp", "--no-start"],
                                  ["remote", "inbox", "myapp"], ["remote", "pause", "--help"],
                                  ["remote", "status"]])
def test_a_command_that_asks_nothing_runs_without_a_terminal(project, fake_remote,
                                                             no_terminal, argv) -> None:
    assert run_cli(argv) == 0
    (call,) = [a for a in fake_remote.calls("ssh") if a[-1] != "handshake"]
    assert "-t" not in call[:-1]


def test_rollback_and_validate(project, fake_remote) -> None:
    assert run_cli(["rollback", "--yes"]) == 0
    assert run_cli(["validate", "--json"]) == 0
    assert _server_argv(fake_remote) == [["rollback", "myapp", "--yes"],
                                         ["validate", "myapp", "--json"]]


def test_remote_passthrough_keeps_arguments_intact(project, fake_remote) -> None:
    assert run_cli(["remote", "logs", "myapp", "--tail", "5"]) == 0
    assert run_cli(["remote", "--", "inbox", "a b"]) == 0
    assert _server_argv(fake_remote) == [["logs", "myapp", "--tail", "5"],
                                         ["inbox", "a b"]]


def test_remote_needs_a_command(project, fake_remote) -> None:
    assert run_cli(["remote"]) == 2
    assert fake_remote.calls() == []


@pytest.mark.parametrize("stdin_tty, stdout_tty, expected", [
    (True, True, True), (True, False, True), (False, True, False), (False, False, False)])
def test_a_terminal_is_one_that_can_answer(monkeypatch, stdin_tty, stdout_tty, expected) -> None:
    """Review of #159 (P3-4): `boxmunge rollback | tee log` has someone at
    the keyboard. ssh -t allocates the server's pty when stdin is a
    terminal, whatever stdout is, and the prompt reaches the pipe; only
    stdin decides whether anyone can answer."""
    from boxmunge_cli import confirming
    monkeypatch.setattr(confirming.sys.stdin, "isatty", lambda: stdin_tty)
    monkeypatch.setattr(confirming.sys.stdout, "isatty", lambda: stdout_tty)
    assert confirming.have_terminal() is expected
